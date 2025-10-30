/* ============================================
   PHISHGUARD AI - MAIN JAVASCRIPT
   ============================================ */

// Global variables
let currentResults = [];
let allResults = [];

// ========== UTILITY FUNCTIONS ==========

/**
 * Show/hide elements
 */
function showElement(id) {
    document.getElementById(id).classList.remove('hidden');
}

function hideElement(id) {
    document.getElementById(id).classList.add('hidden');
}

/**
 * Test URLs for quick demo
 */
function testBenignURL() {
    document.getElementById('urlInput').value = 'https://www.google.com';
}

function testPhishingURL() {
    document.getElementById('urlInput').value = 'http://secure-paypal-verify.com/login';
}

/**
 * Check another URL - reset the form
 */
function checkAnother() {
    document.getElementById('urlForm').reset();
    hideElement('resultsSection');
    hideElement('loadingState');
    document.getElementById('urlInput').focus();
}

// ========== SINGLE URL CHECKING ==========

/**
 * Handle URL form submission
 */
document.getElementById('urlForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const urlInput = document.getElementById('urlInput');
    const url = urlInput.value.trim();
    
    if (!url) {
        showNotification('Please enter a URL', 'error');
        return;
    }
    
    // Validate URL format
    if (!isValidURL(url)) {
        showNotification('Please enter a valid URL', 'error');
        urlInput.classList.add('shake');
        setTimeout(() => urlInput.classList.remove('shake'), 500);
        return;
    }
    
    await checkURL(url);
});

/**
 * Check single URL
 */
async function checkURL(url) {
    // Show loading state
    hideElement('resultsSection');
    showElement('loadingState');
    
    try {
        const response = await fetch('/api/check', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        });
        
        const data = await response.json();
        
        if (data.success) {
            displayResults(data);
        } else {
            showNotification(`Error: ${data.error}`, 'error');
            hideElement('loadingState');
        }
        
    } catch (error) {
        console.error('Error:', error);
        showNotification('Failed to analyze URL. Please try again.', 'error');
        hideElement('loadingState');
    }
}

/**
 * Display analysis results
 */
function displayResults(data) {
    hideElement('loadingState');
    showElement('resultsSection');
    
    // Scroll to results
    document.getElementById('resultsSection').scrollIntoView({ 
        behavior: 'smooth', 
        block: 'start' 
    });
    
    // Update result header
    const resultHeader = document.getElementById('resultHeader');
    const resultIcon = document.getElementById('resultIcon');
    const resultTitle = document.getElementById('resultTitle');
    const resultURL = document.getElementById('resultURL');
    
    if (data.prediction === 1) {
        // Phishing
        resultHeader.className = 'result-header danger';
        resultIcon.className = 'result-icon fas fa-exclamation-triangle';
        resultTitle.textContent = '⚠️ PHISHING DETECTED';
        resultTitle.style.color = '#dc3545';
    } else {
        // Benign
        resultHeader.className = 'result-header safe';
        resultIcon.className = 'result-icon fas fa-check-circle';
        resultTitle.textContent = '✅ SAFE URL';
        resultTitle.style.color = '#28a745';
    }
    
    resultURL.textContent = data.url;
    
    // Update risk level
    const riskBadge = document.querySelector('.risk-badge');
    const riskLabel = document.getElementById('riskLabel');
    
    riskLabel.textContent = data.risk_level.label + ' Risk';
    riskBadge.style.backgroundColor = data.risk_level.color;
    riskBadge.style.color = 'white';
    
    // Update confidence
    document.getElementById('confidenceValue').textContent = 
        data.confidence.toFixed(1) + '%';
    
    // Update probability bars
    updateProbabilityBars(data.probabilities);
    
    // Update insights
    updateInsights(data.insights);
}

/**
 * Update probability visualization
 */
function updateProbabilityBars(probabilities) {
    const benignProb = document.getElementById('benignProb');
    const phishingProb = document.getElementById('phishingProb');
    const benignBar = document.getElementById('benignBar');
    const phishingBar = document.getElementById('phishingBar');
    
    benignProb.textContent = probabilities.benign.toFixed(1) + '%';
    phishingProb.textContent = probabilities.phishing.toFixed(1) + '%';
    
    // Animate bars
    setTimeout(() => {
        benignBar.style.width = probabilities.benign + '%';
        phishingBar.style.width = probabilities.phishing + '%';
    }, 100);
}

/**
 * Update insights section
 */
function updateInsights(insights) {
    // Suspicious insights
    const suspiciousList = document.getElementById('suspiciousList');
    const suspiciousSection = document.getElementById('suspiciousInsights');
    
    suspiciousList.innerHTML = '';
    
    if (insights.suspicious.length > 0) {
        insights.suspicious.forEach(item => {
            const li = document.createElement('li');
            li.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${item.text}`;
            suspiciousList.appendChild(li);
        });
        showElement('suspiciousInsights');
    } else {
        hideElement('suspiciousInsights');
    }
    
    // Safe insights
    const safeList = document.getElementById('safeList');
    const safeSection = document.getElementById('safeInsights');
    
    safeList.innerHTML = '';
    
    if (insights.safe.length > 0) {
        insights.safe.forEach(item => {
            const li = document.createElement('li');
            li.innerHTML = `<i class="fas fa-check-circle"></i> ${item.text}`;
            safeList.appendChild(li);
        });
        showElement('safeInsights');
    } else {
        hideElement('safeInsights');
    }
    
    // Neutral insights
    const neutralList = document.getElementById('neutralList');
    neutralList.innerHTML = '';
    
    if (insights.neutral.length > 0) {
        insights.neutral.forEach(item => {
            const li = document.createElement('li');
            li.innerHTML = `<i class="fas fa-info-circle"></i> ${item.text}`;
            neutralList.appendChild(li);
        });
    }
}

// ========== BATCH URL CHECKING ==========

/**
 * Analyze batch URLs
 */
async function analyzeBatchURLs() {
    const textarea = document.getElementById('urlsTextarea');
    const urls = textarea.value
        .split('\n')
        .map(url => url.trim())
        .filter(url => url);
    
    if (urls.length === 0) {
        showNotification('Please enter at least one URL', 'error');
        return;
    }
    
    if (urls.length > 100) {
        showNotification('Maximum 100 URLs allowed', 'error');
        return;
    }
    
    // Hide input, show progress
    document.querySelector('.checker-card').classList.add('hidden');
    showElement('progressSection');
    
    // Update totals
    document.getElementById('totalCount').textContent = urls.length;
    document.getElementById('processedCount').textContent = '0';
    document.getElementById('percentComplete').textContent = '0%';
    
    try {
        const response = await fetch('/api/check-batch', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ urls: urls })
        });
        
        const data = await response.json();
        
        if (data.success) {
            allResults = data.results;
            displayBatchResults(data);
        } else {
            showNotification(`Error: ${data.error}`, 'error');
        }
        
    } catch (error) {
        console.error('Error:', error);
        showNotification('Failed to analyze URLs. Please try again.', 'error');
    }
    
    hideElement('progressSection');
}

/**
 * Display batch results
 */
function displayBatchResults(data) {
    showElement('batchResults');
    
    // Update summary
    document.getElementById('summaryTotal').textContent = data.summary.total;
    document.getElementById('summarySafe').textContent = data.summary.benign;
    document.getElementById('summaryPhishing').textContent = data.summary.phishing;
    document.getElementById('summaryErrors').textContent = data.summary.errors;
    
    // Display table
    displayResultsTable(data.results);
    
    // Scroll to results
    document.getElementById('batchResults').scrollIntoView({ 
        behavior: 'smooth' 
    });
}

/**
 * Display results in table
 */
function displayResultsTable(results) {
    const tbody = document.getElementById('resultsTableBody');
    tbody.innerHTML = '';
    
    currentResults = results;
    
    results.forEach((result, index) => {
        const row = document.createElement('tr');
        
        // Status
        let statusBadge, riskBadge;
        
        if (!result.success) {
            statusBadge = '<span class="status-badge error">Error</span>';
            riskBadge = '<span class="risk-badge-small" style="background: #6c757d;">N/A</span>';
        } else if (result.prediction === 1) {
            statusBadge = '<span class="status-badge danger">Phishing</span>';
            riskBadge = `<span class="risk-badge-small" style="background: ${result.risk_level.color};">${result.risk_level.label}</span>`;
        } else {
            statusBadge = '<span class="status-badge safe">Benign</span>';
            riskBadge = `<span class="risk-badge-small" style="background: ${result.risk_level.color};">${result.risk_level.label}</span>`;
        }
        
        const confidence = result.success ? 
            `${result.confidence.toFixed(1)}%` : 'N/A';
        
        row.innerHTML = `
            <td>${index + 1}</td>
            <td style="max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${result.url}">
                ${result.url}
            </td>
            <td>${statusBadge}</td>
            <td>${riskBadge}</td>
            <td>${confidence}</td>
            <td>
                ${result.success ? `
                    <button class="btn-icon" onclick="viewDetails(${index})" title="View Details">
                        <i class="fas fa-eye"></i>
                    </button>
                ` : ''}
            </td>
        `;
        
        tbody.appendChild(row);
    });
}

/**
 * Filter batch results
 */
function filterResults() {
    const filterValue = document.getElementById('filterSelect').value;
    
    let filtered = allResults;
    
    if (filterValue === 'phishing') {
        filtered = allResults.filter(r => r.success && r.prediction === 1);
    } else if (filterValue === 'benign') {
        filtered = allResults.filter(r => r.success && r.prediction === 0);
    } else if (filterValue === 'errors') {
        filtered = allResults.filter(r => !r.success);
    }
    
    displayResultsTable(filtered);
}

/**
 * View detailed results for a URL
 */
function viewDetails(index) {
    const result = currentResults[index];
    
    const modal = document.getElementById('detailModal');
    const modalBody = document.getElementById('modalBody');
    
    // Build modal content
    let content = `
        <div class="result-detail">
            <h4>URL Analysis Details</h4>
            <p style="word-break: break-all; font-family: monospace; background: #f3f4f6; padding: 1rem; border-radius: 0.5rem;">
                ${result.url}
            </p>
            
            <div style="margin-top: 1.5rem;">
                <h5>Prediction</h5>
                <p style="font-size: 1.5rem; font-weight: bold; color: ${result.prediction === 1 ? '#dc3545' : '#28a745'};">
                    ${result.prediction_label}
                </p>
                <p>Confidence: <strong>${result.confidence.toFixed(1)}%</strong></p>
                <p>Risk Level: <strong>${result.risk_level.label}</strong></p>
            </div>
            
            <div style="margin-top: 1.5rem;">
                <h5>Probabilities</h5>
                <ul>
                    <li>Benign: ${result.probabilities.benign.toFixed(2)}%</li>
                    <li>Phishing: ${result.probabilities.phishing.toFixed(2)}%</li>
                </ul>
            </div>
    `;
    
    // Add insights
    if (result.insights.suspicious.length > 0) {
        content += `
            <div style="margin-top: 1.5rem;">
                <h5 style="color: #dc3545;">⚠️ Suspicious Indicators</h5>
                <ul>
                    ${result.insights.suspicious.map(i => `<li>${i.text}</li>`).join('')}
                </ul>
            </div>
        `;
    }
    
    if (result.insights.safe.length > 0) {
        content += `
            <div style="margin-top: 1.5rem;">
                <h5 style="color: #28a745;">✓ Safe Indicators</h5>
                <ul>
                    ${result.insights.safe.map(i => `<li>${i.text}</li>`).join('')}
                </ul>
            </div>
        `;
    }
    
    content += `</div>`;
    
    modalBody.innerHTML = content;
    modal.classList.add('active');
}

/**
 * Close modal
 */
function closeModal() {
    document.getElementById('detailModal').classList.remove('active');
}

// Close modal on outside click
document.getElementById('detailModal')?.addEventListener('click', (e) => {
    if (e.target.id === 'detailModal') {
        closeModal();
    }
});

// ========== EXPORT FUNCTIONS ==========

/**
 * Export results as CSV
 */
function exportCSV() {
    if (allResults.length === 0) return;
    
    let csv = 'URL,Prediction,Confidence,Risk Level\n';
    
    allResults.forEach(result => {
        if (result.success) {
            csv += `"${result.url}",${result.prediction_label},${result.confidence.toFixed(1)}%,${result.risk_level.label}\n`;
        } else {
            csv += `"${result.url}",Error,N/A,N/A\n`;
        }
    });
    
    downloadFile(csv, 'phishing-analysis-results.csv', 'text/csv');
}

/**
 * Export results as JSON
 */
function exportJSON() {
    if (allResults.length === 0) return;
    
    const json = JSON.stringify(allResults, null, 2);
    downloadFile(json, 'phishing-analysis-results.json', 'application/json');
}

/**
 * Export single result report
 */
function exportReport() {
    // Get current result data from the page
    const url = document.getElementById('resultURL').textContent;
    const prediction = document.getElementById('resultTitle').textContent;
    const confidence = document.getElementById('confidenceValue').textContent;
    const riskLevel = document.getElementById('riskLabel').textContent;
    
    const report = `
PHISHING URL ANALYSIS REPORT
============================

URL: ${url}
Prediction: ${prediction}
Confidence: ${confidence}
Risk Level: ${riskLevel}

Generated: ${new Date().toLocaleString()}

---
PhishGuard AI - AI-Powered Phishing Detection
    `;
    
    downloadFile(report, 'phishing-report.txt', 'text/plain');
}

/**
 * Helper function to download files
 */
function downloadFile(content, filename, contentType) {
    const blob = new Blob([content], { type: contentType });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
    
    showNotification(`Downloaded: ${filename}`, 'success');
}

// ========== UTILITY FUNCTIONS ==========

/**
 * Validate URL format
 */
function isValidURL(string) {
    try {
        // Add protocol if missing
        if (!string.startsWith('http://') && !string.startsWith('https://')) {
            string = 'http://' + string;
        }
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

/**
 * Show notification
 */
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 1rem 1.5rem;
        background: ${type === 'error' ? '#dc3545' : type === 'success' ? '#28a745' : '#2563eb'};
        color: white;
        border-radius: 0.5rem;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        z-index: 10000;
        animation: slideInRight 0.3s ease-out;
    `;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    // Remove after 3 seconds
    setTimeout(() => {
        notification.style.animation = 'fadeOut 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

/**
 * Format number with commas
 */
function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

// ========== INITIALIZATION ==========

/**
 * Initialize on page load
 */
document.addEventListener('DOMContentLoaded', () => {
    console.log('PhishGuard AI loaded successfully!');
    
    // Focus on URL input if exists
    const urlInput = document.getElementById('urlInput');
    if (urlInput) {
        urlInput.focus();
    }
    
    // Add keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        // ESC to close modal
        if (e.key === 'Escape') {
            closeModal();
        }
    });
});