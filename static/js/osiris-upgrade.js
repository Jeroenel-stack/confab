document.addEventListener("DOMContentLoaded", () => {
    const searchInput = document.getElementById("reportSearch");
    const statusFilter = document.getElementById("statusFilter");
    const rows = document.querySelectorAll(".report-row");

    function filterReports() {
        const query = (searchInput?.value || "").toLowerCase();
        const selectedStatus = statusFilter?.value || "";

        rows.forEach(row => {
            const searchable = (row.dataset.search || "").toLowerCase();
            const status = row.dataset.status || "OPEN";

            const matchesSearch = searchable.includes(query);
            const matchesStatus = !selectedStatus || status === selectedStatus;

            row.style.display = matchesSearch && matchesStatus ? "" : "none";
        });
    }

    if (searchInput) {
        searchInput.addEventListener("input", filterReports);
    }

    if (statusFilter) {
        statusFilter.addEventListener("change", filterReports);
    }
});