/**
 * JobShield Chart & Visual Utilities (charts.js)
 * Helper functions for Chart.js and html2canvas rendering.
 */

window.JobShieldCharts = {
  gaugeChartInstance: null,
  salaryChartInstance: null,

  /**
   * Renders an animated semi-doughnut gauge chart for Trust Score (0 to 100).
   * Green: 70-100, Yellow: 40-69, Red: 0-39
   */
  createTrustGauge: function(canvasId, score) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return null;
    const ctx = canvas.getContext('2d');

    // Destroy existing instance if any
    if (this.gaugeChartInstance) {
      this.gaugeChartInstance.destroy();
    }

    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const trackColor = isDark ? '#1e293b' : '#e2e8f0';

    let fillColor = '#ef4444'; // High Scam Probability (Red)
    if (score >= 70) {
      fillColor = '#10b981'; // Safe / Likely Genuine (Green)
    } else if (score >= 40) {
      fillColor = '#f59e0b'; // Suspicious (Yellow)
    }

    const remaining = 100 - score;

    this.gaugeChartInstance = new Chart(ctx, {
      type: 'doughnut',
      data: {
        datasets: [{
          data: [score, remaining],
          backgroundColor: [fillColor, trackColor],
          borderWidth: 0,
          circumference: 180,
          rotation: 270
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '78%',
        animation: {
          animateRotate: true,
          duration: 1200
        },
        plugins: {
          tooltip: { enabled: false },
          legend: { display: false }
        }
      }
    });

    return this.gaugeChartInstance;
  },

  /**
   * Renders a comparative bar chart comparing offered salary against Indian market benchmarks.
   */
  createSalaryChart: function(canvasId, fresherMedian, tier1Max, offeredVal) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return null;
    const ctx = canvas.getContext('2d');

    if (this.salaryChartInstance) {
      this.salaryChartInstance.destroy();
    }

    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const textColor = isDark ? '#cbd5e1' : '#334155';
    const gridColor = isDark ? '#233354' : '#e2e8f0';

    const isAnomaly = offeredVal > (tier1Max * 1.5);
    const offeredColor = isAnomaly ? '#ef4444' : (offeredVal >= fresherMedian ? '#10b981' : '#f59e0b');

    this.salaryChartInstance = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: ['Fresher Median', 'Tier-1 Max Ceiling', 'Offered in Letter'],
        datasets: [{
          data: [fresherMedian, tier1Max, offeredVal],
          backgroundColor: ['#3b82f6', '#10b981', offeredColor],
          borderRadius: 8,
          barPercentage: 0.6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: function(context) {
                return ` ${context.parsed.y} LPA (INR Lakhs/Year)`;
              }
            }
          }
        },
        scales: {
          y: {
            beginAtZero: true,
            title: { display: true, text: 'Annual CTC in LPA (Lakhs INR)', color: textColor },
            ticks: { color: textColor },
            grid: { color: gridColor }
          },
          x: {
            ticks: { color: textColor },
            grid: { display: false }
          }
        }
      }
    });

    return this.salaryChartInstance;
  },

  /**
   * Captures any DOM card element and triggers an instant PNG image download using html2canvas.
   */
  downloadReportCardImage: function(elementId, filename = 'JobShield_Verification_Report.png') {
    const targetElement = document.getElementById(elementId);
    if (!targetElement) {
      alert('Report element not found to download.');
      return;
    }

    if (typeof html2canvas === 'undefined') {
      alert('html2canvas library is loading. Please try again in a moment.');
      return;
    }

    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';

    html2canvas(targetElement, {
      scale: 2,
      useCORS: true,
      backgroundColor: isDark ? '#111a2e' : '#ffffff'
    }).then(canvas => {
      const link = document.createElement('a');
      link.download = filename;
      link.href = canvas.toDataURL('image/png');
      link.click();
    }).catch(err => {
      console.error('Failed to generate report image:', err);
      alert('Could not export image: ' + err.message);
    });
  }
};
