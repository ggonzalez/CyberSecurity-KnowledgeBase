/**
 * QRNGabri Dashboard – Frontend Logic
 * Charts, live polling, date-range filtering.
 */

'use strict';

// ── Config ─────────────────────────────────────────────────────────────────────
const APP_BASE   = window.location.pathname.replace(/\/[^/]*$/, '') || '';
const API_BASE   = `${APP_BASE}/api`;
const POLL_MS    = 8000;   // How often to refresh live data
const CHART_DEF_DAYS = 7;  // Default lookback
const BIAS_SAFE  = 0.05;
const BIAS_WARN  = 0.10;

// ── State ──────────────────────────────────────────────────────────────────────
let biasChart    = null;
let scatterChart = null;
let autoRefreshTimer = null;

// ── Utility ────────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

function isoDate(d) {
    return d.toISOString().slice(0, 10);
}

function formatHex(hex) {
    if (!hex) return '—';
    return hex.toUpperCase().replace(/^0X/, '0x');
}

function hexToDecimal(hex) {
    try { return BigInt(hex).toString(10); } catch { return '—'; }
}

function hexToBinary(hex, bitCount = 32) {
    try {
        return BigInt(hex).toString(2).padStart(bitCount, '0').replace(/(.{8})/g, '$1 ').trim();
    } catch { return '—'; }
}

function getBiasColor(bias) {
    if (bias < BIAS_SAFE) return '#00ff88';
    if (bias < BIAS_WARN) return '#ffaa00';
    return '#ff4422';
}

function getBiasFillColor(bias) {
    if (bias < BIAS_SAFE) return 'rgba(0,255,136,0.14)';
    if (bias < BIAS_WARN) return 'rgba(255,170,0,0.14)';
    return 'rgba(255,68,34,0.14)';
}

function resolveBiasValue(value, fallback = 0) {
    return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

function computeBiasAxisMax(points) {
    if (!points.length) return 0.10;
    const peak = Math.max(...points.map(point => point.bias), 0.02);
    const padded = peak * 1.20;
    const rounded = Math.ceil(padded * 100) / 100;
    return Math.min(0.50, Math.max(0.03, rounded));
}

function getSelectedReadingBits() {
    const v = Number($('readingBits') ? $('readingBits').value : 1);
    if (!Number.isFinite(v)) return 1;
    return Math.min(8, Math.max(1, v));
}

function getSelectedQualityType() {
    const v = $('qualityBiasType') ? $('qualityBiasType').value : 'raw';
    return ['raw', 'corrected', 'von_neumann'].includes(v) ? v : 'raw';
}

function isVonNeumannShowing() {
    return $('vonNeumannShow') ? $('vonNeumannShow').checked : false;
}

// ── Date range helpers ─────────────────────────────────────────────────────────
function getDefaultRange() {
    const to   = new Date();
    const from = new Date();
    from.setDate(to.getDate() - CHART_DEF_DAYS);
    return { from: isoDate(from), to: isoDate(to) };
}

function getRange() {
    return {
        from: $('dateFrom').value || getDefaultRange().from,
        to:   $('dateTo').value   || getDefaultRange().to,
    };
}

// ── Chart initialisation ───────────────────────────────────────────────────────
function initCharts() {
    Chart.defaults.color          = '#3d5580';
    Chart.defaults.borderColor    = '#1a2e52';
    Chart.defaults.font.family    = "'Share Tech Mono', monospace";

    // Bias line chart: accumulated raw bias after each measurement.
    const biasCtx = $('biasChart').getContext('2d');
    biasChart = new Chart(biasCtx, {
        type: 'line',
        data: {
            datasets: [{
                label: 'Raw Bias',
                data: [],
                borderColor: '#00ffcc',
                backgroundColor: 'rgba(0,255,204,0.15)',
                borderWidth: 2,
                pointRadius: 0,
                pointHoverRadius: 4,
                pointHitRadius: 10,
                tension: 0.18,
                fill: true,
                segment: {
                    borderColor: ctx => getBiasColor(resolveBiasValue(ctx && ctx.p1 && ctx.p1.parsed ? ctx.p1.parsed.y : undefined)),
                    backgroundColor: ctx => getBiasFillColor(resolveBiasValue(ctx && ctx.p1 && ctx.p1.parsed ? ctx.p1.parsed.y : undefined)),
                },
                pointBackgroundColor: ctx => getBiasColor(resolveBiasValue(ctx && ctx.raw ? ctx.raw.y : undefined)),
                pointBorderColor: ctx => getBiasColor(resolveBiasValue(ctx && ctx.raw ? ctx.raw.y : undefined)),
            }, {
                label: 'Corrected Bias',
                data: [],
                borderColor: '#8b5cf6',
                backgroundColor: 'rgba(139,92,246,0.10)',
                borderWidth: 2,
                pointRadius: 0,
                pointHoverRadius: 4,
                pointHitRadius: 10,
                tension: 0.18,
                fill: false,
            }, {
                label: 'Von Neumann',
                data: [],
                borderColor: '#ff6b9d',
                backgroundColor: 'rgba(255,107,157,0.10)',
                borderWidth: 2,
                pointRadius: 0,
                pointHoverRadius: 4,
                pointHitRadius: 10,
                tension: 0.18,
                fill: false,
                hidden: true,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    labels: { color: '#4a6080' },
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    backgroundColor: '#0d1628',
                    borderColor: '#1a2e52',
                    borderWidth: 1,
                    callbacks: {
                        title: ctxArr => {
                            if (!ctxArr.length) return '';
                            const pt = ctxArr[0].raw;
                            const n = ctxArr[0].parsed.x;
                            const v = pt && pt.value !== undefined ? pt.value : null;
                            const rb = getSelectedReadingBits();
                            const valStr = v === null ? '' : rb === 1
                                ? `  ·  0x${v.toString(16).toUpperCase().padStart(4, '0')}`
                                : `  ·  value: ${v}`;
                            return `Measurement #${n}${valStr}`;
                        },
                        label: ctx => {
                            const pct = (ctx.parsed.y * 100).toFixed(3);
                            const dsLabel = ctx.dataset.label || '';
                            return ` ${dsLabel}: ${pct}%`;
                        },
                    },
                },
            },
            scales: {
                x: {
                    type: 'linear',
                    ticks: { color: '#4a6080', maxTicksLimit: 8 },
                    grid: { color: 'rgba(26,46,82,0.25)' },
                    title: {
                        display: true,
                        text: 'Measurement Count',
                        color: '#4a6080',
                    },
                },
                y: {
                    min: 0,
                    max: 0.10,
                    ticks: {
                        color: '#4a6080',
                        callback: value => `${(value * 100).toFixed(1)}%`,
                    },
                    grid:  { color: 'rgba(26,46,82,0.6)' },
                    title: {
                        display: true,
                        text: 'Absolute Bias',
                        color: '#4a6080',
                    },
                },
            },
        },
    });

    // Scatter chart (16-bit values over time)
    const scatterCtx = $('scatterChart').getContext('2d');
    scatterChart = new Chart(scatterCtx, {
        type: 'scatter',
        data: {
            datasets: [{
                label: 'Entropy Sample',
                data: [],
                pointBackgroundColor: 'rgba(0,255,204,0.5)',
                pointBorderColor:     'rgba(0,255,204,0.8)',
                pointRadius: 2,
                pointHoverRadius: 5,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#0d1628',
                    borderColor: '#1a2e52',
                    borderWidth: 1,
                    callbacks: {
                        label: ctx => ` 0x${ctx.parsed.y.toString(16).toUpperCase().padStart(4,'0')}  @ ${new Date(ctx.parsed.x).toLocaleTimeString()}`,
                    },
                },
            },
            scales: {
                x: {
                    type: 'time',
                    time: { tooltipFormat: 'MMM d, HH:mm' },
                    ticks: { color: '#4a6080', maxTicksLimit: 8 },
                    grid:  { color: 'rgba(26,46,82,0.4)' },
                },
                y: {
                    min: 0, max: 65535,
                    ticks: {
                        color: '#4a6080',
                        callback: v => '0x' + v.toString(16).toUpperCase().padStart(4, '0'),
                    },
                    grid: { color: 'rgba(26,46,82,0.4)' },
                },
            },
        },
    });
}

// ── LED helper ─────────────────────────────────────────────────────────────────
function setLED(bias, modularSumEnabled) {
    const container = $('ledContainer');
    const label     = $('healthLabel');
    const good = bias < 0.05 || (bias < 0.2 && modularSumEnabled);

    container.className = 'led-container ' + (good ? 'led-green' : 'led-red');

    if (bias < 0.05) {
        label.textContent  = 'QUANTUM OK';
        label.className    = 'health-label ok';
    } else if (bias < 0.1 || modularSumEnabled) {
        label.textContent  = 'BIAS DETECTED';
        label.className    = 'health-label warn';
    } else {
        label.textContent  = 'BIAS CRITICAL';
        label.className    = 'health-label bad';
    }
}

// ── Hero random number ─────────────────────────────────────────────────────────
function updateHero(row) {
    if (!row) return;
    const el = $('randomNumber');
    const bitCount = Number(row.bit_count || 32);
    el.textContent = formatHex(row.random_hex);
    el.classList.add('updating');
    setTimeout(() => el.classList.remove('updating'), 600);

    $('randomDecimal').textContent = hexToDecimal(row.random_hex);
    $('randomBinary').textContent  = hexToBinary(row.random_hex, bitCount);
    $('randomBitLength').textContent = `${bitCount} bits`;
    $('randomTime').textContent    = row.generated_at
        ? new Date(row.generated_at + 'Z').toLocaleString()
        : '—';
}

async function fetchRandom() {
    try {
        const res = await fetch(`${API_BASE}/random?limit=20`);
        if (!res.ok) return;
        const rows = await res.json();
        if (rows.length > 0) updateHero(rows[0]);
        renderRandomTable(rows);
    } catch (e) {
        console.warn('Random fetch failed', e);
    }
}

async function fetchEntropy() {
    const { from, to } = getRange();
    const readingBits = getSelectedReadingBits();
    const qualityType = getSelectedQualityType();
    try {
        const res = await fetch(`${API_BASE}/entropy?from=${from}&to=${to}&limit=2000&reading_bits=${readingBits}`);
        if (!res.ok) return;
        const data = await res.json();

        const stats   = data.stats   || {};
        const samples = data.samples || [];
        const biasSeriesRaw = data.bias_series_raw || data.bias_series || [];
        const biasSeriesCorrected = data.bias_series_corrected || [];
        const biasSeriesVonNeumann = data.bias_series_von_neumann || [];
        const rawBias = resolveBiasValue(stats.raw_bias, resolveBiasValue(stats.bias, 0));
        const correctedBias = resolveBiasValue(stats.corrected_bias, 0);
        const vonNeumannBias = resolveBiasValue(stats.von_neumann_bias, 0);
        const qualityBias = qualityType === 'corrected' ? correctedBias : 
                            qualityType === 'von_neumann' ? vonNeumannBias : rawBias;

        // Filter bias series to the selected date range for display
        // (bias values are still cumulative from full history – only the visible window changes)
        const filterBySeries = (series) => series.filter(pt => {
            if (!pt.created_at) return true;
            const d = pt.created_at.slice(0, 10); // YYYY-MM-DD
            if (from && d < from) return false;
            if (to   && d > to)   return false;
            return true;
        });
        const visibleRaw       = filterBySeries(biasSeriesRaw);
        const visibleCorrected = filterBySeries(biasSeriesCorrected);
        const visibleVonNeumann = filterBySeries(biasSeriesVonNeumann);

        biasChart.data.datasets[0].data = visibleRaw.map(point => ({
            x: point.measurement,
            y: point.bias,
            value: point.value,
        }));
        biasChart.data.datasets[1].data = visibleCorrected.map(point => ({
            x: point.measurement,
            y: point.bias,
            value: point.value,
        }));
        biasChart.data.datasets[2].data = visibleVonNeumann.map(point => ({
            x: point.measurement,
            y: point.bias,
            value: point.value,
        }));
        biasChart.data.datasets[2].hidden = !isVonNeumannShowing();
        
        const mergedBias = visibleRaw.concat(visibleCorrected).concat(visibleVonNeumann);
        biasChart.options.scales.y.max = computeBiasAxisMax(mergedBias);
        biasChart.data.datasets[0].borderColor = getBiasColor(rawBias);
        biasChart.data.datasets[0].backgroundColor = getBiasFillColor(rawBias);
        biasChart.update();

        // Update scatter chart
        const scatterData = samples.map(s => ({
            x: new Date(s.created_at + 'Z').getTime(),
            y: s.sample_value,
        }));
        scatterChart.data.datasets[0].data = scatterData;
        scatterChart.options.scales.y.max = readingBits === 1 ? 65535 : ((1 << readingBits) - 1);
        scatterChart.options.scales.y.min = 0;
        scatterChart.options.scales.y.ticks.callback = v => {
            if (readingBits === 1) {
                return '0x' + v.toString(16).toUpperCase().padStart(4, '0');
            }
            return v.toString(10);
        };
        scatterChart.update('none');

        // Update bias/stat cards
        $('chartBias').textContent   = `${(rawBias * 100).toFixed(2)}% / ${(correctedBias * 100).toFixed(2)}% / ${(vonNeumannBias * 100).toFixed(2)}%`;
        const totalMeasurements = stats.measurements ?? samples.length;
        const rangeMeasurements = stats.range_measurements ?? totalMeasurements;
        $('chartSamples').textContent = rangeMeasurements !== totalMeasurements
            ? `${rangeMeasurements.toLocaleString()} / ${totalMeasurements.toLocaleString()}`
            : totalMeasurements.toLocaleString();
        $('statBiasQuality').textContent   = qualityBias.toFixed(4);
        $('statBiasRaw').textContent   = rawBias.toFixed(4);
        $('statBiasCorrected').textContent   = correctedBias.toFixed(4);
        if ($('statBiasVonNeumann')) {
            $('statBiasVonNeumann').textContent = vonNeumannBias.toFixed(4);
            $('statBiasVonNeumann').style.color = getBiasColor(vonNeumannBias);
        }
        $('statTotal').textContent  = (stats.total || 0).toLocaleString();
        $('statOnes').textContent   = (stats.ones || 0).toLocaleString();
        $('statZeros').textContent  = (stats.zeros || 0).toLocaleString();
        $('chartBias').style.color = getBiasColor(qualityBias);
        $('statBiasQuality').style.color = getBiasColor(qualityBias);
        $('statBiasRaw').style.color = getBiasColor(rawBias);
        $('statBiasCorrected').style.color = getBiasColor(correctedBias);
        setLED(qualityBias, false);

    } catch (e) {
        console.warn('Entropy fetch failed', e);
    }
}

// ── Table renderers ────────────────────────────────────────────────────────────
function renderRandomTable(rows) {
    const tbody = $('randomTbody');
    if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--dim);padding:1.5rem">No data yet</td></tr>';
        return;
    }
    tbody.innerHTML = rows.map(r => {
        const hex     = formatHex(r.random_hex);
        const dec     = hexToDecimal(r.random_hex);
        const ts      = r.generated_at ? new Date(r.generated_at + 'Z').toLocaleString() : '—';
        const bitsHex = (r.bit_count || 32);
        return `<tr>
            <td style="font-family:var(--display);color:var(--neon);font-size:0.8rem">${hex}</td>
            <td style="color:var(--dim);font-size:0.68rem;max-width:200px;overflow:hidden;text-overflow:ellipsis">${dec}</td>
            <td>${bitsHex}</td>
            <td style="color:var(--dim)">${ts}</td>
        </tr>`;
    }).join('');
}

// ── Refresh orchestration ──────────────────────────────────────────────────────
async function refreshAll() {
    await Promise.all([fetchRandom(), fetchEntropy()]);
}

function startAutoRefresh() {
    clearInterval(autoRefreshTimer);
    autoRefreshTimer = setInterval(refreshAll, POLL_MS);
}

// ── Event listeners ────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    // Set default date range
    const range = getDefaultRange();
    if ($('dateFrom')) $('dateFrom').value = range.from;
    if ($('dateTo'))   $('dateTo').value   = range.to;

    initCharts();
    refreshAll();
    startAutoRefresh();

    const applyBtn = $('applyRange');
    if (applyBtn) {
        applyBtn.addEventListener('click', () => {
            fetchEntropy();
        });
    }

    if ($('readingBits')) {
        $('readingBits').addEventListener('change', () => {
            fetchEntropy();
        });
    }

    if ($('qualityBiasType')) {
        $('qualityBiasType').addEventListener('change', () => {
            fetchEntropy();
        });
    }

    if ($('vonNeumannShow')) {
        $('vonNeumannShow').addEventListener('change', () => {
            biasChart.data.datasets[2].hidden = !isVonNeumannShowing();
            biasChart.update();
        });
    }
});
