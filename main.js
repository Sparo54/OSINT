/* =========================================================================
   OFT (Operation Find Them) — main process
   Sections:
     1. Imports
     2. Small helpers
     3. Port / service reference data
     4. Port probing (used by Port Tester + ports handler)
     5. DNS-over-HTTPS helper
     6. Tool handlers (H) — one function per tool, grouped by category
     7. IPC wiring
     8. Window creation
   ========================================================================= */

const { app, BrowserWindow, ipcMain, shell } = require('electron')
const path = require('path')
const dns = require('dns').promises
const net = require('net')
const tls = require('tls')
const os = require('os')
const { execFile, spawn } = require('child_process')

/* ---------- 2. Small helpers ------------------------------------------- */

// fetch with a sane timeout baked in
const J = (url, opts) => fetch(url, { signal: AbortSignal.timeout(12000), ...opts })

// basic allow-list for anything that becomes a hostname/IP in a shell call or URL
const okHost = h => /^[a-zA-Z0-9.:_-]{1,253}$/.test(h || '')

// run a Windows CLI command and resolve with its combined output
const sh = (cmd, args, timeoutMs = 60000) =>
  new Promise(resolve => {
    execFile(cmd, args, { timeout: timeoutMs, windowsHide: true }, (err, stdout, stderr) => {
      resolve(stdout || stderr || String(err))
    })
  })

const isIP = net.isIP
const revIP = ip => ip.split('.').reverse().join('.')

/* ---------- 3. Port / service reference data ---------------------------- */

const PORT_SERVICES = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 69: 'TFTP',
  80: 'HTTP', 110: 'POP3', 123: 'NTP', 135: 'MS-RPC', 139: 'NetBIOS',
  143: 'IMAP', 161: 'SNMP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB',
  465: 'SMTPS', 587: 'SMTP-Submission', 636: 'LDAPS', 993: 'IMAPS',
  995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP',
  5060: 'SIP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
  8000: 'HTTP-Alt', 8080: 'HTTP-Proxy/Alt', 8443: 'HTTPS-Alt',
  8888: 'HTTP-Alt', 9200: 'Elasticsearch', 27017: 'MongoDB'
}

// ports that are "really" UDP services; we still only probe them over TCP
// and label that clearly in the result
const UDP_SERVICES = new Set([53, 69, 123, 161, 5060])

/* ---------- 4. Port probing ---------------------------------------------- */

function probePort(host, port, timeoutMs = 2500) {
  return new Promise(resolve => {
    const socket = new net.Socket()
    const startedAt = Date.now()
    let banner = ''
    let state = 'filtered'

    const finish = () => {
      socket.destroy()
      resolve({
        port,
        protocol: UDP_SERVICES.has(port) ? 'TCP (also UDP)' : 'TCP',
        service: PORT_SERVICES[port] || 'unknown',
        state,
        banner: banner.trim().slice(0, 80),
        ms: Date.now() - startedAt,
        time: new Date().toISOString()
      })
    }

    socket.setTimeout(timeoutMs)

    socket.on('connect', () => {
      state = 'open'
      if ([80, 8080, 8000, 8888].includes(port)) socket.write('HEAD / HTTP/1.0\r\n\r\n')
      socket.setTimeout(900) // short grace period to catch a banner/response
    })

    socket.on('data', chunk => {
      banner += chunk.toString('utf8').replace(/[^\x20-\x7e\n]/g, '')
      finish()
    })

    socket.on('timeout', finish)

    socket.on('error', err => {
      state = err.code === 'ECONNREFUSED' ? 'closed' : 'filtered'
      finish()
    })

    socket.connect(port, host)
  })
}

/* ---------- 5. DNS-over-HTTPS helper ------------------------------------- */

const dnsOverHttps = async (name, type) =>
  (await (await J(`https://dns.google/resolve?name=${name}&type=${type}`)).json())

/* ---------- 6. Tool handlers ---------------------------------------------
   Every entry here is invoked from the renderer via ipcMain 'run' below,
   as H[toolName](args). Keep each handler's return shape JSON-friendly —
   it gets rendered directly or exported to JSON/CSV/TXT by the UI.
   -------------------------------------------------------------------- */

const H = {

  /* -- IP intelligence ------------------------------------------------- */

  async ip(query) {
    if (query && !okHost(query)) return { error: 'Invalid input' }

    const fields = 'status,message,country,countryCode,regionName,city,zip,lat,lon,' +
                    'timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query'
    const r = await (await J(`http://ip-api.com/json/${query}?fields=${fields}`)).json()
    if (r.status !== 'success') return { error: r.message }

    r.ip_type = r.hosting ? 'datacenter/hosting' : r.mobile ? 'mobile' : 'likely residential/business'
    r.vpn_proxy_flag = r.proxy
    r.note = 'Geolocation is approximate. Tor check: use Threat Intel.'
    return r
  },

  /* -- DNS & domain intelligence ---------------------------------------- */

  async dns(query) {
    if (!okHost(query)) return { error: 'Enter a domain or IP' }
    if (isIP(query)) return { ptr: await dns.reverse(query).catch(e => e.code) }

    const out = {}
    for (const type of ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']) {
      out[type] = await dns.resolve(query, type).catch(e => e.code)
    }

    // SPF lives inside TXT records
    const txtJoined = Array.isArray(out.TXT) ? out.TXT.map(a => a.join('')) : []
    out.SPF = txtJoined.find(x => x.startsWith('v=spf1')) || 'none'

    // DMARC lives at _dmarc.<domain>
    const dmarc = await dns.resolveTxt('_dmarc.' + query).catch(() => [])
    out.DMARC = dmarc.map(a => a.join(''))[0] || 'none'

    // DKIM: probe a handful of common selectors
    out.DKIM = {}
    for (const selector of ['default', 'google', 'selector1', 'selector2', 'k1']) {
      const rec = await dns.resolveTxt(`${selector}._domainkey.${query}`).catch(() => null)
      if (rec) out.DKIM[selector] = rec.map(a => a.join('')).join('').slice(0, 90) + '…'
    }
    if (!Object.keys(out.DKIM).length) out.DKIM = 'no common selectors found'

    // reverse lookup every A record we found
    if (Array.isArray(out.A)) {
      out.PTR = await Promise.all(out.A.map(ip => dns.reverse(ip).catch(() => 'none')))
    }

    return out
  },

  async dnssec(domain) {
    const r = await dnsOverHttps(domain, 'DS')
    return {
      domain,
      dnssec_validated: r.AD,
      ds_records: r.Answer || 'none',
      status: r.Status
    }
  },

  async whois(query) {
    const kind = isIP(query) ? 'ip' : 'domain'
    const r = await J(`https://rdap.org/${kind}/${query}`)
    if (!r.ok) return { error: 'RDAP ' + r.status }

    const d = await r.json()
    return {
      name: d.name || d.ldhName,
      handle: d.handle,
      status: d.status,
      nameservers: (d.nameservers || []).map(n => n.ldhName),
      events: d.events,
      country: d.country,
      startAddress: d.startAddress,
      endAddress: d.endAddress
    }
  },

  /* -- Network diagnostics ------------------------------------------------ */

  ping: query => okHost(query) ? sh('ping', ['-n', '4', query]) : 'Invalid host',

  tracert: query => okHost(query) ? sh('tracert', ['-d', '-h', '20', query]) : 'Invalid host',

  async tcp(query) {
    const [host, portStr] = query.split(':')
    if (!okHost(host) || !portStr) return 'Format: host:port'
    return probePort(host, +portStr)
  },

  async net() {
    const gatewayLines = (await sh('ipconfig', [])).match(/Default Gateway[ .]*: (\S+)/g) || []
    const publicIp = async url => (await (await J(url)).text()).trim()

    return {
      hostname: os.hostname(),
      platform: os.platform() + ' ' + os.release(),
      public_ipv4: await publicIp('https://api.ipify.org').catch(() => 'unreachable'),
      public_ipv6: await publicIp('https://api64.ipify.org').catch(() => 'unreachable'),
      default_gateways: gatewayLines.map(g => g.split(': ')[1]),
      interfaces: os.networkInterfaces()
    }
  },

  /* -- Port & service analysis -------------------------------------------- */

  async ports({ host, ports }) {
    if (!okHost(host)) return []

    const results = []
    const queue = [...ports]
    const WORKERS = 64 // parallel probes

    await Promise.all(
      Array.from({ length: WORKERS }, async () => {
        while (queue.length) results.push(await probePort(host, queue.shift()))
      })
    )

    return results.sort((a, b) => a.port - b.port)
  },

  /* -- Web & TLS intelligence ---------------------------------------------- */

  tls: hostname => new Promise(resolve => {
    const socket = tls.connect(
      { host: hostname, port: 443, servername: hostname, rejectUnauthorized: false, timeout: 8000 },
      () => {
        const cert = socket.getPeerCertificate()
        const daysRemaining = Math.round((new Date(cert.valid_to) - Date.now()) / 864e5)

        resolve({
          subject: cert.subject,
          issuer: cert.issuer,
          valid_from: cert.valid_from,
          valid_to: cert.valid_to,
          days_remaining: daysRemaining,
          expired: daysRemaining < 0,
          SANs: cert.subjectaltname,
          protocol: socket.getProtocol(),
          cipher: socket.getCipher().name,
          authorized: socket.authorized,
          authError: socket.authorizationError,
          fingerprint256: cert.fingerprint256
        })
        socket.end()
      }
    )
    socket.on('error', err => resolve({ error: err.message }))
    socket.on('timeout', () => { resolve({ error: 'timeout' }); socket.destroy() })
  }),

  async headers(query) {
    let url = query.startsWith('http') ? query : 'https://' + query
    const chain = []
    let lastResponse

    for (let i = 0; i < 10; i++) {
      const r = await J(url, { redirect: 'manual' })
      chain.push({ url, status: r.status })
      lastResponse = r

      const location = r.headers.get('location')
      if (!location) break
      url = new URL(location, url).href
    }

    const headers = Object.fromEntries(lastResponse.headers)
    const securityHeaderNames = [
      'strict-transport-security', 'content-security-policy', 'x-frame-options',
      'x-content-type-options', 'referrer-policy', 'permissions-policy'
    ]

    return {
      redirect_chain: chain,
      security_headers: Object.fromEntries(securityHeaderNames.map(k => [k, headers[k] || 'MISSING'])),
      server: headers.server || 'hidden',
      all_headers: headers
    }
  },

  /* -- Threat intelligence & reputation ------------------------------------- */

  async threat(ip) {
    if (isIP(ip) !== 4) return { error: 'Enter an IPv4 address' }

    const result = { ip }

    const torList = (await (await J('https://check.torproject.org/torbulkexitlist')).text()).split('\n')
    result.tor_exit_node = torList.includes(ip)

    const blocklistZones = [
      'zen.spamhaus.org', 'b.barracudacentral.org', 'bl.spamcop.net', 'dnsbl.dronebl.org'
    ]
    result.blocklists = {}
    for (const zone of blocklistZones) {
      result.blocklists[zone] = await dns.resolve4(`${revIP(ip)}.${zone}`)
        .then(() => 'LISTED', () => 'not listed')
    }

    result.evidence_links = {
      AbuseIPDB: `https://www.abuseipdb.com/check/${ip}`,
      VirusTotal: `https://www.virustotal.com/gui/ip-address/${ip}`,
      GreyNoise: `https://viz.greynoise.io/ip/${ip}`,
      AlienVault_OTX: `https://otx.alienvault.com/indicator/ip/${ip}`,
      Shodan: `https://www.shodan.io/host/${ip}`
    }

    return result
  },

  /* -- OSINT & infrastructure mapping ---------------------------------------- */

  async crt(domain) {
    const r = await (await J(`https://crt.sh/?q=%25.${domain}&output=json`)).json()
    return [...new Set(r.flatMap(x => x.name_value.split('\n')))].sort()
  }
}

/* ---------- 7. IPC wiring -------------------------------------------------- */

ipcMain.handle('run', (event, toolName, args) =>
  Promise.resolve()
    .then(() => H[toolName](args))
    .catch(err => ({ error: err.message }))
)

ipcMain.handle('open', (event, url) => {
  if (/^https:\/\//.test(url)) shell.openExternal(url)
})

// opens a real terminal outside the app window: a native Windows CMD
// window, or a cloud shell in the default browser
ipcMain.handle('terminal', (event, kind) => {
  try {
    if (kind === 'cmd') {
      spawn('cmd.exe', [], { detached: true, stdio: 'ignore', cwd: os.homedir() }).unref()
      return { ok: true }
    }
    if (kind === 'cloudshell') {
      // Google Cloud Shell; swap this URL if a different provider is preferred
      shell.openExternal('https://shell.cloud.google.com/?show=terminal')
      return { ok: true }
    }
    return { ok: false, error: 'unknown terminal type' }
  } catch (err) {
    return { ok: false, error: err.message }
  }
})

/* ---------- 8. Window creation ---------------------------------------------- */

app.whenReady().then(() => {
  const win = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 1000,
    minHeight: 650,
    backgroundColor: '#07050a',
    autoHideMenuBar: true,
    title: 'OFT — Operation Find Them',
    show: false, // avoid a flash of an unfocused window; shown once ready below
    webPreferences: {
      preload: path.join(__dirname, 'preload.js')
    }
  })

  win.loadFile('index.html')

  win.once('ready-to-show', () => {
    win.show()
    win.focus()
    win.webContents.focus()
  })
})

app.on('window-all-closed', () => app.quit())
