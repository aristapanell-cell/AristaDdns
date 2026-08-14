class AristaDNSHub {
    constructor() {
        this.dnsData = [];
        this.filteredData = [];
        this.currentPage = 1;
        this.pageSize = 50;
        this.currentFilter = 'all';
        this.searchQuery = '';
        this.metadata = {
            total: 0,
            updated_at: null
        };
        this.stats = null;

        this.init();
    }

    async init() {
        try {
            await this.loadData();
            this.setupEventListeners();
            this.render();
        } catch (error) {
            console.error('Failed to initialize DNS Hub:', error);
            this.showError();
        }
    }

    async loadData() {
        const response = await fetch('data/dns.json', {
            cache: 'no-cache'
        });

        if (!response.ok) {
            throw new Error('Failed to load DNS data');
        }

        const data = await response.json();

        this.dnsData = Array.isArray(data.dns)
            ? data.dns
            : [];

        this.metadata = {
            total: Number.isFinite(data.total)
                ? data.total
                : this.dnsData.length,
            updated_at: data.updated_at || null
        };

        try {
            const statsResponse = await fetch('data/stats.json', {
                cache: 'no-cache'
            });

            if (statsResponse.ok) {
                this.stats = await statsResponse.json();
            }
        } catch (error) {
            console.warn('Failed to load stats:', error);
            this.stats = null;
        }

        this.filteredData = [...this.dnsData];
    }

    setupEventListeners() {
        const searchInput = document.getElementById('searchInput');

        if (searchInput) {
            searchInput.addEventListener('input', event => {
                this.searchQuery = event.target.value
                    .trim()
                    .toLowerCase();

                this.currentPage = 1;
                this.filterData();
                this.render();
            });
        }

        document.querySelectorAll('.filter-btn').forEach(button => {
            button.addEventListener('click', () => {
                document.querySelectorAll('.filter-btn').forEach(btn => {
                    btn.classList.remove('active');
                });

                button.classList.add('active');
                this.currentFilter = button.dataset.filter || 'all';
                this.currentPage = 1;

                this.filterData();
                this.render();
            });
        });

        const prevPage = document.getElementById('prevPage');

        if (prevPage) {
            prevPage.addEventListener('click', () => {
                if (this.currentPage > 1) {
                    this.currentPage--;
                    this.render();
                }
            });
        }

        const nextPage = document.getElementById('nextPage');

        if (nextPage) {
            nextPage.addEventListener('click', () => {
                const totalPages = Math.ceil(
                    this.filteredData.length / this.pageSize
                );

                if (this.currentPage < totalPages) {
                    this.currentPage++;
                    this.render();
                }
            });
        }

        const retryBtn = document.getElementById('retryBtn');

        if (retryBtn) {
            retryBtn.addEventListener('click', () => {
                const modal = document.getElementById('errorModal');

                if (modal) {
                    modal.style.display = 'none';
                }

                this.init();
            });
        }
    }

    filterData() {
        this.filteredData = this.dnsData.filter(dns => {
            let matchesFilter = true;

            if (this.currentFilter !== 'all') {
                if (this.currentFilter === 'IPv4') {
                    matchesFilter = dns.type === 'IPv4';
                } else if (this.currentFilter === 'IPv6') {
                    matchesFilter = dns.type === 'IPv6';
                } else {
                    const categories = Array.isArray(dns.categories)
                        ? dns.categories
                        : [];

                    const protocols = Array.isArray(dns.protocols)
                        ? dns.protocols
                        : [];

                    matchesFilter =
                        categories.includes(this.currentFilter) ||
                        protocols.includes(this.currentFilter);
                }
            }

            if (!matchesFilter) {
                return false;
            }

            if (!this.searchQuery) {
                return true;
            }

            const searchable = [
                dns.address,
                dns.provider,
                dns.name,
                dns.doh_url,
                dns.dot,
                dns.hostname,
                dns.port,
                dns.type,
                dns.protocol,
                ...(Array.isArray(dns.categories)
                    ? dns.categories
                    : []),
                ...(Array.isArray(dns.protocols)
                    ? dns.protocols
                    : [])
            ]
                .filter(value => value !== null && value !== undefined)
                .map(value => String(value).toLowerCase());

            return searchable.some(value =>
                value.includes(this.searchQuery)
            );
        });
    }

    render() {
        this.updateStats();
        this.renderDNS();
        this.updatePagination();
    }

    updateStats() {
        const totalDns = document.getElementById('totalDns');
        const lastUpdated = document.getElementById('lastUpdated');

        if (totalDns) {
            totalDns.textContent = this.metadata.total;
        }

        if (lastUpdated) {
            lastUpdated.textContent =
                this.formatDate(this.metadata.updated_at);
        }

        if (!this.stats) {
            return;
        }

        this.setText('dashTotal', this.stats.total_dns);
        this.setText('dashIPv4', this.stats.total_ipv4);
        this.setText('dashIPv6', this.stats.total_ipv6);
        this.setText('dashDoH', this.stats.total_doh);
        this.setText('dashDoT', this.stats.total_dot);
        this.setText('dashAdBlock', this.stats.total_adblock);
        this.setText('dashFamily', this.stats.total_family);
        this.setText('dashSecurity', this.stats.total_security);
    }

    setText(id, value) {
        const element = document.getElementById(id);

        if (element) {
            element.textContent = value ?? 0;
        }
    }

    renderDNS() {
        const container = document.getElementById('dnsContainer');
        const emptyState = document.getElementById('emptyState');

        if (!container || !emptyState) {
            return;
        }

        const start =
            (this.currentPage - 1) * this.pageSize;

        const pageData = this.filteredData.slice(
            start,
            start + this.pageSize
        );

        if (!pageData.length) {
            container.innerHTML = '';
            emptyState.style.display = 'block';
            return;
        }

        emptyState.style.display = 'none';

        container.innerHTML = pageData
            .map(dns => this.createDNSCard(dns))
            .join('');

        container
            .querySelectorAll('.copy-btn')
            .forEach(button => {
                button.addEventListener('click', () => {
                    this.copyToClipboard(
                        button.dataset.address || '',
                        button
                    );
                });
            });
    }

    createDNSCard(dns) {
        const categories = Array.isArray(dns.categories)
            ? dns.categories
            : [];

        const protocols = Array.isArray(dns.protocols)
            ? dns.protocols
            : [];

        const categoriesHtml = categories
            .map(category =>
                `<span class="category-badge">${this.escapeHtml(category)}</span>`
            )
            .join('');

        const protocolsHtml = protocols
            .map(protocol =>
                `<span class="protocol-badge">${this.escapeHtml(protocol)}</span>`
            )
            .join('');

        const displayAddress = this.getDisplayAddress(dns);
        const copyAddress = displayAddress;

        const provider =
            dns.provider ||
            dns.name ||
            'Unknown Provider';

        const type =
            dns.type ||
            dns.protocol ||
            'Unknown';

        return `
            <div class="dns-card glass-card">
                <div class="dns-header">
                    <span class="dns-address">${this.escapeHtml(displayAddress)}</span>
                    <span class="dns-status">● ACTIVE</span>
                </div>

                <div class="dns-provider">
                    ${this.escapeHtml(provider)}
                </div>

                <div class="dns-categories">
                    ${categoriesHtml}
                </div>

                <div class="dns-protocols">
                    ${protocolsHtml}
                </div>

                <div class="dns-type">
                    ${this.escapeHtml(type)}
                </div>

                <div class="dns-actions">
                    <button
                        class="copy-btn"
                        data-address="${this.escapeHtml(copyAddress)}"
                    >
                        Copy
                    </button>
                </div>
            </div>
        `;
    }

    getDisplayAddress(dns) {
        if (
            typeof dns.doh_url === 'string' &&
            dns.doh_url.trim()
        ) {
            return dns.doh_url;
        }

        if (
            typeof dns.dot === 'string' &&
            dns.dot.trim()
        ) {
            return dns.dot;
        }

        if (
            typeof dns.address === 'string' &&
            dns.address.trim()
        ) {
            return dns.address;
        }

        return 'N/A';
    }

    updatePagination() {
        const totalPages = Math.max(
            1,
            Math.ceil(
                this.filteredData.length / this.pageSize
            )
        );

        const prevBtn = document.getElementById('prevPage');
        const nextBtn = document.getElementById('nextPage');
        const pageInfo = document.getElementById('pageInfo');

        if (prevBtn) {
            prevBtn.disabled = this.currentPage <= 1;
        }

        if (nextBtn) {
            nextBtn.disabled =
                this.currentPage >= totalPages;
        }

        if (pageInfo) {
            pageInfo.textContent =
                `Page ${this.currentPage} of ${totalPages}`;
        }
    }

    async copyToClipboard(text, button) {
        if (!text) {
            return;
        }

        try {
            await navigator.clipboard.writeText(text);

            button.textContent = 'Copied!';
            button.classList.add('copied');

            setTimeout(() => {
                button.textContent = 'Copy';
                button.classList.remove('copied');
            }, 2000);
        } catch (error) {
            console.error('Failed to copy:', error);
        }
    }

    formatDate(dateString) {
        if (!dateString) {
            return 'Never';
        }

        const date = new Date(dateString);

        if (Number.isNaN(date.getTime())) {
            return String(dateString);
        }

        return date.toLocaleString('en-US', {
            month: 'short',
            day: 'numeric',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    escapeHtml(value) {
        return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    showError() {
        const modal = document.getElementById('errorModal');

        if (modal) {
            modal.style.display = 'block';
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new AristaDNSHub();
});
