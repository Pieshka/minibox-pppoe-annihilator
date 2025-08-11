// @license magnet:?xt=urn:btih:d3d9a9a6595521f9666a5e94cc830dab83b65699&dn=expat.txt Expat

/////////////////////////
//                     //
// Minibox Main Script //
//                     //
/////////////////////////

/* Our API endpoint */
const mnbox_api_url = "/cgi-bin/webapi";

/* Shared API service object */
window.mnbox_apiService = {
    async makeRequest(payload)
    {
        try
        {
            const token = sessionStorage.getItem('mnbox_super_secret_token');
            if(!token)
            {
                window.mnbox_authService.openLoginDialog(); // Hope we got one on our page
                throw new Error('Minibox token not found');
            }

            const res = await fetch(mnbox_api_url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Minibox-Auth': token
                },
                body: JSON.stringify(payload),
                credentials: 'include'
            });

            if(res.status === 403)
            {
                window.mnbox_authService.clearToken();
                window.mnbox_authService.openLoginDialog();
                throw new Error('Session expired');
            }

            if(res.status === 500)
            {
                window.location.href = '/fatal.html';
                throw new Error('Fatal error');
            }

            return res.json();
        }
        catch (e)
        {
            console.error('[MNBOX-API] Error: ', e);
        }
    },

    async getConfig()
    {
        return this.makeRequest({ action: 'get_config' });
    },

    async setConfig(data)
    {
        return this.makeRequest({
            action: 'set_config',
            data: data
        });
    },

    async getServices()
    {
        return this.makeRequest({ action: 'get_services' });
    },

    async getIpInfo()
    {
        return this.makeRequest({ action: 'get_ipinfo' });
    },

    async getInterfaces()
    {
        return this.makeRequest({ action: 'get_interfaces' });
    },

    async restart()
    {
        return this.makeRequest({ action: 'restart' });
    },

    async shutdown()
    {
        return this.makeRequest({ action: 'shutdown' });
    },

    async changePassword(password)
    {
        return this.makeRequest({
            action: 'change_password',
            data: {
                username: 'root',
                password: password
            }
        });
    },

    async checkAlive(checkIp = null)
    {
        try
        {
            let url = '/cgi-bin/alive';

            if(checkIp)
                url = `http://${checkIp}/cgi-bin/alive`
            
            const res = await fetch(url, {
                method: 'GET'
            });

            const text = await res.text();
            return text.trim() == "yes I'm alive";
        } 
        catch(e)
        {
            return false;
        }
    },

    async waitForReboot(timeout = 120, interval = 2, checkIp = null)
    {
        const startTime = Date.now();
        const endTime = startTime + timeout * 1000;

        while (Date.now() < endTime)
        {
            
            try
            {
                const isAlive = await this.checkAlive(checkIp);
                if(isAlive) return true;
            }
            catch (e) {} // We are ignoring errors while waiting

            await new Promise(resolve => setTimeout(resolve, interval*1000));
        }

        return false;
    }
}

/* Now our authentication module */
window.mnbox_authService = null;
window.mnbox_getAuthService = function() {
    return {
        token: null,
        password: '',
        errorMsg: '',
        isLoggedIn: false,

        init() 
        {
            window.mnbox_authService = this;
            this.loadToken();

            if(!this.token)
                this.openLoginDialog();
            else
            {
                this.isLoggedIn = true;
                this.closeLoginDialog();
                window.dispatchEvent(new CustomEvent('mnbox-logged-in'));
            }
        },

        openLoginDialog()
        {
            this.errorMsg = '';
            this.password = '';
            this.isLoggedIn = false;
            this.$refs.dialog.showModal();
        },

        closeLoginDialog()
        {
            this.$refs.dialog.close();
        },

        loadToken()
        {
            this.token = sessionStorage.getItem('mnbox_super_secret_token');
        },

        saveToken(token)
        {
            this.token = token;
            sessionStorage.setItem('mnbox_super_secret_token', token);
            this.isLoggedIn = true;
            window.dispatchEvent(new CustomEvent('mnbox-logged-in'));
        },

        clearToken()
        {
            this.token = null;
            sessionStorage.removeItem('mnbox_super_secret_token');
            this.isLoggedIn = false;
        },

        async doLogin()
        {
            this.errorMsg = '';
            const pwd = this.password.trim();
            if(!pwd)
            {
                this.errorMsg = window.AlpineI18n.t('login_dialog.password_empty');
                return;
            }

            try
            {
                const res = await fetch(mnbox_api_url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        action: 'authenticate',
                        data: {
                            username: 'root', // Hehe
                            password: pwd
                        }
                    }),
                    credentials: 'include'
                });

                if(res.status === 403)
                {
                    this.errorMsg = window.AlpineI18n.t('login_dialog.invalid_password');
                    return;
                }

                if(!res.ok)
                {
                    this.errorMsg = window.AlpineI18n.t('login_dialog.login_error');
                    return;
                }

                const response = await res.json();
                if(!response.data.token)
                    return;

                this.saveToken(response.data.token);
                this.closeLoginDialog();
            }
            catch(e)
            {
                console.error('[MNBOX-API] Network Error:',e);
            }
        },

        logout()
        {
            this.clearToken();
            this.openLoginDialog();
        }
    }
}

/* Base page for all subpages */
window.mnbox_basePage = {
    showLoading: false,
    loadingText: '',
    saveStatus: '',
    saveStatusClass: '',
    isLoggedIn: false,

    initBase()
    {
        this.isLoggedIn = window.mnbox_authService.isLoggedIn;
        this.loadingText = window.AlpineI18n.t('basic.loading_text');

        /* Listen for authentication state changes */
        window.addEventListener('mnbox-logged-in', ()=>{
            this.isLoggedIn = true;
            this.fetchData();
        });

        /* Fetch data now if already logged in or open login dialog */
        if(this.isLoggedIn)
            this.fetchData();
        else
            window.mnbox_authService.openLoginDialog();
    },

    async saveWithReboot(configData)
    {
        try
        {
            this.showLoading = true;
            this.loadingText = window.AlpineI18n.t('basic.saving_changes_text');
            this.saveStatus = window.AlpineI18n.t('basic.saving_changes_text');
            this.saveStatusClass = 'mnbox-color-neutral';

            /* Save configuration */
            await window.mnbox_apiService.setConfig(configData);

            /* Check if we are still logged in */
            if(!window.mnbox_authService.isLoggedIn)
            {
                this.saveStatus = window.AlpineI18n.t('basic.saving_changes_session_expired');
                this.saveStatusClass = 'mnbox-color-warning';
                this.showLoading = false;
                return;
            }

            /* Trigger reboot */
            this.loadingText = window.AlpineI18n.t('basic.saving_changes_rebooting');
            this.saveStatus = window.AlpineI18n.t('basic.saving_changes_rebooting');
            this.saveStatusClass = 'mnbox-color-good';
            await window.mnbox_apiService.restart();

            /* Wait for Minibox to come back online on specified IP if mask /32.
               If not - well hope we got this right
            */
            let targetIp = window.location.hostname;
            if(configData.lan_mask === 32 && targetIp != configData.lan_ip)
                targetIp = configData.lan_ip;

            const isAlive = await window.mnbox_apiService.waitForReboot(120, 2, targetIp);

            if(isAlive)
            {
                this.saveStatus = window.AlpineI18n.t('basic.saving_changes_done');
                this.saveStatusClass = 'mnbox-color-good';
                if(configData.lan_mask === 32 && targetIp == configData.lan_ip)
                    this.fetchData();
                else
                    window.location.href = `http://${targetIp}/`;
            }
            else
            {
                this.saveStatus = window.AlpineI18n.t('basic.saving_changes_timeout');
                this.saveStatusClass = 'mnbox-color-warning';
            }
        }
        catch (e)
        {
            console.error('[MNBOX-API] Error:', e);
            this.saveStatus = window.AlpineI18n.t('basic.saving_changes_error');
            this.saveStatusClass = 'mnbox-color-fail';
        }
        finally
        {
            this.showLoading = false;
        }
    }
}

/* Status page */
window.mnbox_statusPage = function() {
    return {
        ...window.mnbox_basePage,

        wan: {
            if: '',
            status: '',
            statusClass: ''
        },

        vlan: {
            if: '',
            id: 1,
            pcp: 0,
            status: '',
            statusClass: '',
            show: false
        },

        ppp: {
            if: '',
            status: '',
            statusClass: ''
        },

        lan: {
            if: '',
            status: '',
            statusClass: ''
        },

        dhcpd: {
            status: '',
            statusClass: ''
        },

        pppd: {
            status: '',
            statusClass: ''
        },

        httpd: {
            status: '',
            statusClass: ''
        },

        ips: {
            ppp: '',
            gw: '',
            lan: '',
            dns1: '',
            dns2: '',

            showGw: false,
            showDns1: false,
            showDns2: false
        },

        async fetchData()
        {
            if(!window.mnbox_authService.isLoggedIn)
                return;

            try
            {
                this.showLoading = true;

                /* Load various statuses and configuration */
                const [interfaces, services, ipinfo, config] = await Promise.all([
                    window.mnbox_apiService.getInterfaces(),
                    window.mnbox_apiService.getServices(),
                    window.mnbox_apiService.getIpInfo(),
                    window.mnbox_apiService.getConfig()
                ]);

                /* Normally Minibox should expose WAN as eth0
                   and LAN as eth1, but we can't be sure.
                   So I'll try to guess them but it's better
                   to hardcode or maybe create new API endpoint.
                */
                const ifs = Object.entries(interfaces.data)
                .filter(([key]) => !key.toLowerCase().includes('ppp'))
                .sort((a,b) => {
                    const numA = parseInt(a[0].match(/\d+$/)[0]);
                    const numB = parseInt(b[0].match(/\d+$/)[0]);
                    return numA - numB;
                });

                /* Load interfaces */
                this.wan.if = ifs[0][0]; // WAN
                [this.wan.status, this.wan.statusClass] = this.getSimpleStatusNameAndClass(ifs[0][1]);

                this.lan.if = ifs[1][0]; // LAN
                [this.lan.status, this.lan.statusClass] = this.getSimpleStatusNameAndClass(ifs[1][1]);

                if(config.data.use_vlan) // VLAN
                {
                    this.vlan.id = config.data.vlan_id;
                    this.vlan.pcp = config.data.vlan_pcp;
                    this.vlan.if = `${this.wan.if}.${this.vlan.id}`;
                    [this.vlan.status, this.vlan.statusClass] = this.getSimpleStatusNameAndClass(interfaces.data[this.vlan.if]);
					this.vlan.show = true;
                }

                this.ppp.if = 'ppp0'; // I hope two PPP clients won't awake
                [this.ppp.status, this.ppp.statusClass] = 
                this.getPppIfStatusNameAndClass(
                    interfaces.data.ppp0, 
                    services.data.pppd, 
                    (config.data.pppoe_user !== ""));
                
                /* Load services */
                if(config.data.lan_dhcp)
                    [this.dhcpd.status, this.dhcpd.statusClass] = this.getSimpleStatusNameAndClass(services.data.udhcpd);
                else
                    [this.dhcpd.status, this.dhcpd.statusClass] = [window.AlpineI18n.t('status_page.not_configured'), 'mnbox-color-neutral'];
                
                [this.pppd.status, this.pppd.statusClass] = this.getSimpleStatusNameAndClass(services.data.pppd);
                [this.httpd.status, this.httpd.statusClass] = this.getSimpleStatusNameAndClass(services.data.httpd);

                /* Load IP information */
                /* IP should be shown only when PPPoE is up */
                /* Otherwise we are on the default IP which is unknown for the API */
                this.ips.ppp = ipinfo.data.ppp_ip;
                if(interfaces.data.ppp0 === "up" || interfaces.data.ppp0 === "unknown")
                    if(config.data.lan_mask === 32)
                    {
                        this.ips.gw = ipinfo.data.ppp_gw;
                        this.ips.lan = config.data.lan_ip;
                        this.ips.showGw = true;
                    }
                    else
                        this.ips.lan = ipinfo.data.ppp_gw;

                const dnsList = ipinfo.data.ppp_dns?.trim().split(" ").filter(Boolean) || [];
				if (dnsList.length > 0) 
				{
					this.ips.dns1 = dnsList[0];
					this.ips.showDns1 = true;

					if(dnsList.length > 1) 
					{
						this.ips.dns2 = dnsList[1];
						this.ips.showDns2 = true;
					}
				}
                this.showLoading = false;
            }
            catch(e)
            {
                console.error('[MNBOX-API] Error:', e);
                this.showLoading = false;
            }
        },

        getSimpleStatusNameAndClass(status) // I love long names
        {
            switch(status)
            {
                case 'up':
                case 'unknown': // Kernel devs says that unknown is most likely up
                case 1:
				case true:
                    return [window.AlpineI18n.t('status_page.active'), 'mnbox-color-good'];
                default:
                    return [window.AlpineI18n.t('status_page.inactive'), 'mnbox-color-fail'];
            }
        },

        getPppIfStatusNameAndClass(ifStatus, clientStatus, clientConfigured)
        {
            switch(clientStatus)
            {
                case true:
                    switch(ifStatus)
                    {
                        case 'up':
                        case 'unknown':
                            return [window.AlpineI18n.t('status_page.active'), 'mnbox-color-good'];
                        default:
                            return [window.AlpineI18n.t('status_page.connecting'), 'mnbox-color-warning'];
                    }
                default:
                    switch(clientConfigured)
                    {
                        case false:
                            return [window.AlpineI18n.t('status_page.not_configured'), 'mnbox-color-neutral'];
                        default:
                            return [window.AlpineI18n.t('status_page.inactive'), 'mnbox-color-fail'];
                    }
            }
        }
    }
}

/* WAN/LAN page */
window.mnbox_configPage = function() {
    return {
        ...window.mnbox_basePage,

        config: {},

        /* For LAN page */
        showIp: false,

        async fetchData()
        {
            if(!window.mnbox_authService.isLoggedIn)
                return;

            try
            {
                this.showLoading = true;

                /* Load configuration and thats it :P */
                this.config = (await window.mnbox_apiService.getConfig()).data;
                if(this.config.lan_mask === 32) this.showIp = true;
                
                this.showLoading = false;
            }
            catch(e)
            {
                console.error('[MNBOX-API] Error:', e);
                this.showLoading = false;
            }
        },
    }
}

/* Security page */
window.mnbox_securityPage = function() {
    return {
        ...window.mnbox_basePage,

        new_password: '',
        repeat_password: '',

        async fetchData()
        {
            /* There is no need to fetch anything */
        },

        async savePassword()
        {
			this.saveStatus = '';
			this.saveStatusClass = '';
			
            /* Very simple procedure */
            if (this.new_password !== this.repeat_password)
            {
                this.saveStatus = window.AlpineI18n.t('security_page.password_not_match');
                this.saveStatusClass = 'mnbox-color-fail';
                return;
            }

            try
            {
                const result = await window.mnbox_apiService.changePassword(this.new_password);

                if(result.status === "error")
                {
                    this.saveStatus = window.AlpineI18n.t('security_page.password_set_error');
                    this.saveStatusClass = 'mnbox-color-fail';
                    return;
                }

                this.saveStatus = window.AlpineI18n.t('security_page.password_set_success');
                this.saveStatusClass = 'mnbox-color-good';

                /* And logout of course */
                window.mnbox_authService.logout();
            }
            catch (e)
            {
                console.error('[MNBOX-API] Error:', e);
            }
        }
    }
}

/* Device page */
window.mnbox_devicePage = function () {
    return {
        ...window.mnbox_basePage,

        loadingBusy: true,

        async fetchData()
        {
            /* There is no need to fetch anything */
        },

        async doReboot()
        {
            this.loadingText = window.AlpineI18n.t('device_page.reboot_dialog');
            this.loadingBusy = true;
            this.showLoading = true;

            /* Invoke reboot */
            const res = await window.mnbox_apiService.restart();
            if(res.status === "error")
            {
                this.showLoading = false;
            }

            /* Wait for Minibox to come back online */
            const isAlive = await window.mnbox_apiService.waitForReboot();

            if(isAlive)
                this.showLoading = false;
        },

        async doShutdown()
        {
            this.loadingText = window.AlpineI18n.t('device_page.shutdown_dialog');
            this.loadingBusy = false;
            this.showLoading = true;

            /* Invoke shutdown */
            const res = await window.mnbox_apiService.shutdown();
            if(res.status === "error")
            {
                this.showLoading = false;
            }
        }
    }
}

// @license-end