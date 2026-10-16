'use strict';

/**
 * captable.js — single source of truth for all cap-table mathematics.
 *
 * Design principles:
 *  - Share counts are INTEGERS (whole shares). No fractional shares anywhere.
 *  - All percentages are computed as integer basis points (1 bp = 0.01%),
 *    then distributed with the largest-remainder method so displayed
 *    percentages ALWAYS sum to exactly 100.00%.
 *  - Nothing about vesting / ownership / dilution is stored as a "cached"
 *    figure for reads — it is always recomputed from the raw inputs so the
 *    table is live and correct at any point in time.
 */

const BPS_TOTAL = 10000; // 100.00%

const toDate = (v) => {
  if (!v) return null;
  const d = new Date(v);
  return isNaN(d.getTime()) ? null : d;
};

/**
 * Linear time-based vesting with an optional cliff.
 * Returns an integer number of whole vested shares, always in [0, total].
 */
function computeVestedShares(vestingStart, vestingEnd, cliffDate, totalShares, now = new Date()) {
  const total = Number(totalShares);
  if (!Number.isFinite(total) || total <= 0) return 0;

  const start = toDate(vestingStart);
  const end = toDate(vestingEnd);

  // No vesting schedule => everything is vested (e.g. founders, purchasers).
  if (!start || !end) return Math.floor(total);
  if (end <= start) return Math.floor(total);

  if (now < start) return 0;
  if (now >= end) return Math.floor(total);
  if (cliffDate) {
    const cliff = toDate(cliffDate);
    if (cliff && now < cliff) return 0;
  }

  const totalDuration = end.getTime() - start.getTime();
  const elapsed = now.getTime() - start.getTime();
  const ratio = Math.min(Math.max(elapsed / totalDuration, 0), 1);
  return Math.floor(total * ratio);
}

/**
 * Derive a shareholder status from the vesting schedule and clock.
 * Always recomputed for live display.
 * Returns one of: 'unvested' | 'vesting' | 'fully_vested' | 'active'.
 */
function computeShareholderStatus(vestingStart, vestingEnd, cliffDate, totalShares, now = new Date()) {
  const start = toDate(vestingStart);
  const end = toDate(vestingEnd);
  if (!start || !end) return 'active';

  if (now < start) return 'unvested';
  if (now >= end) return 'fully_vested';

  if (cliffDate) {
    const cliff = toDate(cliffDate);
    if (cliff && now < cliff) return 'unvested';
  }
  return 'vesting';
}

function assertValidShares(raw, field = 'shares') {
  // Reject fractional input BEFORE any truncation (parseInt(1.5) === 1 would
  // otherwise silently smuggle a fractional request through as "1").
  if (raw !== null && raw !== undefined && raw !== '') {
    const asNum = Number(raw);
    if (!Number.isFinite(asNum)) {
      const err = new Error(`${field} must be a number`);
      err.status = 400;
      throw err;
    }
    if (!Number.isInteger(asNum)) {
      const err = new Error(`${field} must be a whole number (no fractions)`);
      err.status = 400;
      throw err;
    }
  }
  const shares = typeof raw === 'number' ? raw : parseInt(raw);
  if (!Number.isInteger(shares)) {
    const err = new Error(`${field} must be a whole number (no fractions)`);
    err.status = 400;
    throw err;
  }
  if (shares < 0) {
    const err = new Error(`${field} cannot be negative`);
    err.status = 400;
    throw err;
  }
}

function assertValidVesting(vestingStart, vestingEnd, cliffDate) {
  const start = toDate(vestingStart);
  const end = toDate(vestingEnd);
  const cliff = toDate(cliffDate);

  if (vestingStart && !start) { const e = new Error('Invalid vesting_start date'); e.status = 400; throw e; }
  if (vestingEnd && !end) { const e = new Error('Invalid vesting_end date'); e.status = 400; throw e; }
  if (cliffDate && !cliff) { const e = new Error('Invalid cliff_date'); e.status = 400; throw e; }

  if (start && end && end <= start) {
    const e = new Error('vesting_end must be after vesting_start'); e.status = 400; throw e;
  }
  if (start && end && cliff && (cliff < start || cliff > end)) {
    const e = new Error('cliff_date must fall between vesting_start and vesting_end'); e.status = 400; throw e;
  }
}

// ---------------------------------------------------------------------------
// Convertibles (SAFEs / notes) and pricing
// ---------------------------------------------------------------------------

function safePricePerShare(round) {
  const r = round || {};
  const v = r.valuation_amount ?? r.pre_money_valuation ?? 0;
  const pps = r.price_per_share ?? null;
  if (pps && pps > 0) return pps;
  return v > 0 ? v : 0;
}

function safeDenom(round) {
  const r = round || {};
  const d = r.pre_shares || r.fully_diluted_pre_shares || r.new_shares || 1;
  return d > 0 ? d : 1;
}

/**
 * Shares a SAFE / note converts into. Effective price is the LOWER of the
 * cap price and the discount price. Rounds UP so the investor is never shorted.
 */
function convertibleShares(conv, round) {
  const principal = Number(conv.amount) || 0;
  if (principal <= 0) return 0;

  const roundPPS = safePricePerShare(round);
  const discount = conv.discount != null ? Number(conv.discount) : 0;

  let price = roundPPS;
  if (conv.cap_amount && roundPPS > 0) {
    const capPrice = conv.cap_amount / safeDenom(round);
    if (capPrice < price) price = capPrice;
  }
  if (discount > 0) {
    const discPrice = roundPPS * (1 - discount);
    if (discPrice < price) price = discPrice;
  }

  if (price <= 0) return 0;
  return Math.ceil(principal / price);
}

// ---------------------------------------------------------------------------
// Percentage allocation (largest remainder over integer basis points)
// ---------------------------------------------------------------------------

function allocateBps(entries) {
  const totalWeight = entries.reduce((s, e) => s + (Number(e.weight) || 0), 0);
  if (totalWeight <= 0) {
    return new Map(entries.map((e) => [e.key, 0]));
  }

  const raw = entries.map((e) => {
    const w = Number(e.weight) || 0;
    const exact = (w / totalWeight) * BPS_TOTAL;
    return { key: e.key, exact, floor: Math.floor(exact) };
  });

  let allocated = raw.reduce((s, e) => s + e.floor, 0);
  let remainder = BPS_TOTAL - allocated;

  raw.sort((a, b) => {
    const fa = a.exact - a.floor;
    const fb = b.exact - b.floor;
    if (fb - fa !== 0) return fb - fa;
    return a.key < b.key ? -1 : 1;
  });
  for (const e of raw) {
    if (remainder <= 0) break;
    e.floor += 1;
    remainder -= 1;
  }

  return new Map(raw.map((e) => [e.key, e.floor]));
}

const bpsToPct = (bps) => (bps / 100).toFixed(2); // 1234 -> "12.34"

/**
 * recompute() — the live aggregation. Pure function: given raw pools, active
 * shareholders, and outstanding convertibles, produce every derived figure.
 * Call on every read so the table is always current.
 */
function recompute({ pools = [], holders = [], convertibles = [], now = new Date() } = {}) {
  const safeHolders = holders.map((h) => {
    const shares = Number(h.shares_owned) || 0;
    const vested = computeVestedShares(h.vesting_start, h.vesting_end, h.cliff_date, shares, now);
    const derivedStatus = computeShareholderStatus(h.vesting_start, h.vesting_end, h.cliff_date, shares, now);
    return {
      ...h,
      shares_owned: shares,
      vested_shares: vested,
      unvested_shares: shares - vested,
      derived_status: derivedStatus
    };
  });

  const totalOutstanding = safeHolders.reduce((s, h) => s + h.shares_owned, 0);
  const totalVested = safeHolders.reduce((s, h) => s + h.vested_shares, 0);
  const totalAuthorized = pools.reduce((s, p) => s + (Number(p.total_shares) || 0), 0);
  const totalUnissued = Math.max(totalAuthorized - totalOutstanding, 0);

  const outstandingEntries = safeHolders.map((h) => ({ key: h.id, weight: h.shares_owned }));
  const outstandingBps = allocateBps(outstandingEntries);

  let safeShares = 0;
  const perConvertible = convertibles.map((c) => {
    const sh = convertibleShares(c, convertibles._round);
    safeShares += sh;
    return { ...c, converted_shares: sh };
  });
  const fullyDilutedShares = totalOutstanding + totalUnissued + safeShares;

  const fdEntries = safeHolders.map((h) => ({ key: h.id, weight: h.shares_owned }));
  const fdBps = allocateBps(fdEntries);

  const enrichedHolders = safeHolders.map((h) => {
    const obps = outstandingBps.get(h.id) || 0;
    const fbps = fdBps.get(h.id) || 0;
    return {
      ...h,
      ownership_pct: bpsToPct(obps),
      ownership_bps: obps,
      fd_ownership_pct: bpsToPct(fbps),
      fd_ownership_bps: fbps
    };
  });

  const poolBreakdown = pools.map((p) => {
    const issued = safeHolders
      .filter((h) => h.equity_pool_id === p.id)
      .reduce((s, h) => s + h.shares_owned, 0);
    const authorized = Number(p.total_shares) || 0;
    const remaining = authorized - issued;
    return {
      id: p.id,
      name: p.name,
      class: p.class,
      authorized,
      issued,
      remaining,
      over_issued: remaining < 0,
      percent_issued: authorized > 0 ? ((issued / authorized) * 100).toFixed(2) : '0.00'
    };
  });

  return {
    total_authorized: totalAuthorized,
    total_outstanding: totalOutstanding,
    total_unissued: totalUnissued,
    total_vested: totalVested,
    total_unvested: totalOutstanding - totalVested,
    fully_diluted: fullyDilutedShares,
    convertible_shares: safeShares,
    convertibles: perConvertible,
    shareholder_count: enrichedHolders.length,
    pool_count: pools.length,
    pools: poolBreakdown,
    holders: enrichedHolders,
    ownership_pct_sum: bpsToPct(enrichedHolders.reduce((s, h) => s + h.ownership_bps, 0)),
    fd_ownership_pct_sum: bpsToPct(enrichedHolders.reduce((s, h) => s + h.fd_ownership_bps, 0))
  };
}

/**
 * simulateDilution() — preview a new issuance WITHOUT mutating anything.
 * Returns per-holder before/after % and post-money figures.
 */
function simulateDilution({ pools = [], holders = [], convertibles = [], newShares = 0, roundValuation = null, newPoolId = null, now = new Date() } = {}) {
  const before = recompute({ pools, holders, convertibles, now });

  const postHolders = holders.slice();
  if (newShares > 0) {
    const targetPool = newPoolId
      ? pools.find((p) => p.id === newPoolId) || pools[0]
      : pools[0];
    postHolders.push({
      id: '__new_investor__',
      name: 'New Issuance',
      shares_owned: newShares,
      equity_pool_id: targetPool ? targetPool.id : null
    });
  }
  const postPools = pools.map((p) =>
    newPoolId && p.id === newPoolId ? { ...p, total_shares: (p.total_shares || 0) + newShares } : p
  );
  const after = recompute({ pools: postPools, holders: postHolders, convertibles, now });

  const perHolder = before.holders.map((h) => {
    const afterH = after.holders.find((a) => a.id === h.id);
    return {
      id: h.id,
      name: h.name,
      shares: h.shares_owned,
      before_pct: h.ownership_pct,
      after_pct: afterH ? afterH.ownership_pct : h.ownership_pct,
      before_fd_pct: h.fd_ownership_pct,
      after_fd_pct: afterH ? afterH.fd_ownership_pct : h.fd_ownership_pct
    };
  });

  const pricePerShare = newShares > 0 && roundValuation
    ? roundValuation / (before.fully_diluted + newShares)
    : null;

  return {
    new_shares: newShares,
    price_per_share: pricePerShare,
    post_money_valuation: roundValuation || null,
    fully_diluted_before: before.fully_diluted,
    fully_diluted_after: after.fully_diluted,
    holders: perHolder
  };
}

/**
 * verify() — ledger self-check. Returns a list of human-readable problems
 * (empty array == healthy). Used by GET /api/cap-table/verify.
 */
function verify({ pools = [], holders = [], events = [] } = {}) {
  const problems = [];

  // 1. No pool over-issued; no negative authorized.
  for (const p of pools) {
    const issued = holders
      .filter((h) => h.equity_pool_id === p.id)
      .reduce((s, h) => s + (Number(h.shares_owned) || 0), 0);
    if (issued > (Number(p.total_shares) || 0)) {
      problems.push(`Pool "${p.name}" is over-issued: ${issued} issued > ${p.total_shares} authorized`);
    }
    if ((Number(p.total_shares) || 0) < 0) {
      problems.push(`Pool "${p.name}" has negative authorized shares`);
    }
  }

  // 2. Share conservation: sum of event deltas == outstanding shares.
  const outstanding = holders.reduce((s, h) => s + (Number(h.shares_owned) || 0), 0);
  let eventDelta = 0;
  for (const e of events) {
    if (e.delta_shares != null) eventDelta += Number(e.delta_shares) || 0;
    else if (e.shares_after != null && e.shares_before != null) {
      eventDelta += (Number(e.shares_after) || 0) - (Number(e.shares_before) || 0);
    }
  }
  if (eventDelta !== outstanding) {
    problems.push(`Ledger mismatch: event deltas sum to ${eventDelta} but outstanding is ${outstanding}`);
  }

  // 3. No negative holdings.
  for (const h of holders) {
    const owned = Number(h.shares_owned) || 0;
    if (owned < 0) problems.push(`Shareholder "${h.name}" has negative shares`);
  }

  return problems;
}

module.exports = {
  BPS_TOTAL,
  computeVestedShares,
  computeShareholderStatus,
  assertValidShares,
  assertValidVesting,
  convertiblesToShares: convertibleShares,
  allocateBps,
  bpsToPct,
  recompute,
  simulateDilution,
  verify
};

