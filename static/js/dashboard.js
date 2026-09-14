/* CE-UEBA dashboard charts (Chart.js). Data comes from /api/dashboard-data. */

const CE_COLORS = {
  raw: "rgba(229, 72, 77, 0.65)",
  rawBorder: "rgba(229, 72, 77, 1)",
  adjusted: "rgba(56, 217, 195, 0.65)",
  adjustedBorder: "rgba(56, 217, 195, 1)",
  severity: ["#e5484d", "#f76b15", "#f5d90a", "#46a758"],
  active: "#7a4de0",
  suppressed: "#3f5878",
  department: "#5b93c7",
  grid: "rgba(147, 163, 188, 0.15)",
};

const chartInstances = {};

document.addEventListener("DOMContentLoaded", () => {
  const filterForm = document.getElementById("alert-filters");
  if (filterForm) {
    document.getElementById("filter-auto-hint").hidden = false;
    filterForm.querySelectorAll("select").forEach((select) => {
      select.addEventListener("change", () => filterForm.requestSubmit());
    });
  }

  const params = window.location.search || "";
  fetch("/api/dashboard-data" + params)
    .then((response) => {
      if (!response.ok) {
        throw new Error("HTTP " + response.status);
      }
      return response.json();
    })
    .then((payload) => renderCharts(payload))
    .catch((error) => {
      document.querySelectorAll(".chart-error").forEach((el) => {
        el.textContent = "Chart data is currently unavailable.";
      });
      console.error("CE-UEBA chart error:", error);
    });
});

function renderCharts(payload) {
  if (typeof Chart === "undefined" || !payload.summary.total_anomalies) {
    document.querySelectorAll(".chart-error").forEach((el) => {
      el.textContent = typeof Chart === "undefined"
        ? "Charts could not load. Review the scores in the table above."
        : "No matching alerts to chart. Clear filters to explore the demo.";
      el.setAttribute("role", "status");
      el.parentElement.querySelector("canvas").hidden = true;
    });
    return;
  }
  Chart.defaults.color = "#b7c5d9";
  Chart.defaults.font.family = '"Segoe UI", sans-serif';
  const charts = payload.charts || {};
  rawVsAdjusted(charts.raw_vs_adjusted);
  severityChart(charts.severity_breakdown);
  suppressionChart(charts.suppression_breakdown);
  departmentChart(charts.department_breakdown);
}

function makeChart(canvasId, config) {
  const canvas = document.getElementById(canvasId);
  if (!canvas || typeof Chart === "undefined") {
    return;
  }
  if (chartInstances[canvasId]) {
    chartInstances[canvasId].destroy();
  }
  chartInstances[canvasId] = new Chart(canvas, config);
}

function rawVsAdjusted(data) {
  if (!data || !data.labels.length) return;
  makeChart("rawAdjustedChart", {
    type: "bar",
    data: {
      labels: data.labels,
      datasets: [
        {
          label: "Raw risk (simulated)",
          data: data.raw_scores,
          backgroundColor: CE_COLORS.raw,
          borderColor: CE_COLORS.rawBorder,
          borderWidth: 1,
        },
        {
          label: "Context-adjusted risk",
          data: data.adjusted_scores,
          backgroundColor: CE_COLORS.adjusted,
          borderColor: CE_COLORS.adjustedBorder,
          borderWidth: 1,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { grid: { color: CE_COLORS.grid } },
        y: { beginAtZero: true, max: 100, grid: { color: CE_COLORS.grid } },
      },
      plugins: { legend: { position: "bottom" } },
    },
  });
}

function severityChart(data) {
  if (!data || !data.labels.length) return;
  makeChart("severityChart", {
    type: "doughnut",
    data: {
      labels: data.labels,
      datasets: [
        {
          data: data.counts,
          backgroundColor: CE_COLORS.severity,
          borderColor: "#111a2b",
          borderWidth: 2,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: "bottom" } },
    },
  });
}

function suppressionChart(data) {
  if (!data || !data.labels.length) return;
  makeChart("suppressionChart", {
    type: "doughnut",
    data: {
      labels: data.labels,
      datasets: [
        {
          data: data.counts,
          backgroundColor: [CE_COLORS.active, CE_COLORS.suppressed],
          borderColor: "#111a2b",
          borderWidth: 2,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: "bottom" } },
    },
  });
}

function departmentChart(data) {
  if (!data || !data.labels.length) return;
  makeChart("departmentChart", {
    type: "bar",
    data: {
      labels: data.labels,
      datasets: [
        {
          label: "Alerts",
          data: data.counts,
          backgroundColor: "rgba(91, 147, 199, 0.65)",
          borderColor: CE_COLORS.department,
          borderWidth: 1,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { grid: { color: CE_COLORS.grid } },
        y: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: CE_COLORS.grid } },
      },
      plugins: { legend: { display: false } },
    },
  });
}
