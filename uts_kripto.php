<?php
session_start();

function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }

$action = $_POST['action'] ?? '';
$result = null;
$error  = null;

switch ($action) {

    case 'caesar_encrypt':
    case 'caesar_decrypt':
        $text  = $_POST['caesar_text']  ?? '';
        $shift = (int)($_POST['caesar_shift'] ?? 3);
        $shift = (($shift % 26) + 26) % 26;

        if ($action === 'caesar_decrypt') $shift = (26 - $shift) % 26;

        $output = '';
        foreach (str_split($text) as $ch) {
            if (ctype_upper($ch))      $output .= chr((ord($ch) - 65 + $shift) % 26 + 65);
            elseif (ctype_lower($ch))  $output .= chr((ord($ch) - 97 + $shift) % 26 + 97);
            else                       $output .= $ch;
        }
        $result = [
            'tool'  => 'Caesar Cipher',
            'op'    => ($action === 'caesar_encrypt') ? 'Enkripsi' : 'Dekripsi',
            'input' => $text,
            'shift' => $shift,
            'out'   => $output,
        ];
        break;

    case 'xor_encrypt':
    case 'xor_decrypt':
        $text = $_POST['xor_text'] ?? '';
        $key  = $_POST['xor_key']  ?? '';

        if ($key === '') { $error = 'Kunci XOR tidak boleh kosong.'; break; }

        if ($action === 'xor_decrypt') {
            if (!ctype_xdigit(str_replace(' ', '', $text))) {
                $error = 'Input dekripsi harus berupa string hex (0-9 a-f).';
                break;
            }
            $bytes = hex2bin(str_replace(' ', '', $text));
        } else {
            $bytes = $text;
        }

        $keyLen = strlen($key);
        $xored  = '';
        for ($i = 0; $i < strlen($bytes); $i++) {
            $xored .= chr(ord($bytes[$i]) ^ ord($key[$i % $keyLen]));
        }

        if ($action === 'xor_encrypt') {
            $hexOut = strtoupper(bin2hex($xored));
            $result = [
                'tool'  => 'XOR Cipher',
                'op'    => 'Enkripsi',
                'input' => $text,
                'key'   => $key,
                'out'   => $hexOut,
            ];
        } else {
            $result = [
                'tool'  => 'XOR Cipher',
                'op'    => 'Dekripsi',
                'input' => $text,
                'key'   => $key,
                'out'   => $xored,
            ];
        }
        break;

    case 'sha256':
        $text = $_POST['sha_text'] ?? '';
        $hash = hash('sha256', $text);
        $result = [
            'tool'  => 'SHA-256',
            'op'    => 'Hash',
            'input' => $text,
            'out'   => $hash,
            'len'   => strlen($hash) * 4 . ' bit (' . strlen($hash) . ' hex chars)',
        ];
        break;

    case 'rsa_generate':
        $bits = (int)($_POST['rsa_bits'] ?? 2048);
        if (!in_array($bits, [1024, 2048, 4096])) $bits = 2048;

        $cfg = [
            'digest_alg'       => 'sha256',
            'private_key_bits' => $bits,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];
        $res = openssl_pkey_new($cfg);
        if (!$res) { $error = 'openssl_pkey_new gagal: ' . openssl_error_string(); break; }

        openssl_pkey_export($res, $privPEM);
        $details = openssl_pkey_get_details($res);
        $pubPEM  = $details['key'];

        $_SESSION['rsa_priv'] = $privPEM;
        $_SESSION['rsa_pub']  = $pubPEM;

        $result = [
            'tool' => 'RSA',
            'op'   => 'Generate Key Pair',
            'bits' => $bits,
            'priv' => $privPEM,
            'pub'  => $pubPEM,
        ];
        break;

    case 'rsa_encrypt':
        $plain  = $_POST['rsa_plain'] ?? '';
        $pubPEM = $_POST['rsa_pub_key'] ?? ($_SESSION['rsa_pub'] ?? '');

        if (!$pubPEM) { $error = 'Public key kosong. Generate dulu atau tempel manual.'; break; }

        $pubKey = openssl_pkey_get_public($pubPEM);
        if (!$pubKey) { $error = 'Public key tidak valid.'; break; }

        if (!openssl_public_encrypt($plain, $encrypted, $pubKey)) {
            $error = 'Enkripsi RSA gagal. Pesan terlalu panjang untuk ukuran kunci?';
            break;
        }
        $result = [
            'tool'  => 'RSA',
            'op'    => 'Enkripsi',
            'input' => $plain,
            'out'   => base64_encode($encrypted),
        ];
        break;

    case 'rsa_decrypt':
        $cipher  = $_POST['rsa_cipher'] ?? '';
        $privPEM = $_POST['rsa_priv_key'] ?? ($_SESSION['rsa_priv'] ?? '');

        if (!$privPEM) { $error = 'Private key kosong.'; break; }

        $privKey = openssl_pkey_get_private($privPEM);
        if (!$privKey) { $error = 'Private key tidak valid.'; break; }

        if (!openssl_private_decrypt(base64_decode($cipher), $decrypted, $privKey)) {
            $error = 'Dekripsi RSA gagal.';
            break;
        }
        $result = [
            'tool'  => 'RSA',
            'op'    => 'Dekripsi',
            'input' => $cipher,
            'out'   => $decrypted,
        ];
        break;

    case 'sig_generate_key':
        $cfg = ['digest_alg' => 'sha256', 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA];
        $res = openssl_pkey_new($cfg);
        if (!$res) { $error = 'Gagal membuat kunci tanda tangan.'; break; }
        openssl_pkey_export($res, $privPEM);
        $pubPEM = openssl_pkey_get_details($res)['key'];
        $_SESSION['sig_priv'] = $privPEM;
        $_SESSION['sig_pub']  = $pubPEM;
        $result = ['tool' => 'Digital Signature', 'op' => 'Generate Key', 'priv' => $privPEM, 'pub' => $pubPEM];
        break;

    case 'sig_sign':
        $doc     = $_POST['sig_doc']      ?? '';
        $privPEM = $_POST['sig_priv_key'] ?? ($_SESSION['sig_priv'] ?? '');

        if (!$privPEM) { $error = 'Private key kosong.'; break; }
        $privKey = openssl_pkey_get_private($privPEM);
        if (!$privKey) { $error = 'Private key tidak valid.'; break; }

        if (!openssl_sign($doc, $sig, $privKey, OPENSSL_ALGO_SHA256)) {
            $error = 'Gagal membuat tanda tangan.'; break;
        }
        $result = [
            'tool'  => 'Digital Signature',
            'op'    => 'Sign',
            'doc'   => $doc,
            'sig'   => base64_encode($sig),
        ];
        break;

    case 'sig_verify':
        $doc    = $_POST['sig_doc_v']   ?? '';
        $sigB64 = $_POST['sig_sig_v']   ?? '';
        $pubPEM = $_POST['sig_pub_key'] ?? ($_SESSION['sig_pub'] ?? '');

        if (!$pubPEM) { $error = 'Public key kosong.'; break; }
        $pubKey = openssl_pkey_get_public($pubPEM);
        if (!$pubKey) { $error = 'Public key tidak valid.'; break; }

        $ok = openssl_verify($doc, base64_decode($sigB64), $pubKey, OPENSSL_ALGO_SHA256);
        $result = [
            'tool'   => 'Digital Signature',
            'op'     => 'Verify',
            'doc'    => $doc,
            'status' => $ok === 1 ? '✅ VALID — Tanda tangan sah!' : '❌ TIDAK VALID — Dokumen mungkin dimodifikasi!',
            'ok'     => $ok === 1,
        ];
        break;
}

$tabMap = [
    'caesar_encrypt' => 'caesar', 'caesar_decrypt' => 'caesar',
    'xor_encrypt'    => 'xor',    'xor_decrypt'    => 'xor',
    'sha256'         => 'sha256',
    'rsa_generate'   => 'rsa',    'rsa_encrypt'    => 'rsa',    'rsa_decrypt' => 'rsa',
    'sig_generate_key' => 'sig',  'sig_sign' => 'sig',          'sig_verify'  => 'sig',
];
$activeTab = $tabMap[$action] ?? 'caesar';
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🔐 KriptoLab — Web Tools Kriptografi</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@400;600;800&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
    --bg:       #0b0f19;
    --surface:  #131929;
    --card:     #1a2238;
    --border:   #2a3655;
    --accent:   #00e5ff;
    --accent2:  #ff6b6b;
    --accent3:  #a8ff78;
    --text:     #e4eaf8;
    --muted:    #5e7097;
    --radius:   12px;
    --mono:     'Space Mono', monospace;
    --sans:     'Syne', sans-serif;
}

html { font-size: 16px; }
body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    background-image:
        radial-gradient(ellipse 80% 50% at 20% -10%, rgba(0,229,255,.07) 0%, transparent 60%),
        radial-gradient(ellipse 60% 40% at 90% 100%, rgba(168,255,120,.05) 0%, transparent 60%);
}

.wrap { max-width: 960px; margin: 0 auto; padding: 0 20px 80px; }

header {
    padding: 48px 0 32px;
    text-align: center;
    position: relative;
}
header::after {
    content: '';
    display: block;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--accent), transparent);
    margin-top: 32px;
}
.brand {
    font-size: clamp(2rem, 6vw, 3.2rem);
    font-weight: 800;
    letter-spacing: -1px;
    line-height: 1;
}
.brand span { color: var(--accent); }
.subtitle {
    margin-top: 10px;
    color: var(--muted);
    font-family: var(--mono);
    font-size: .8rem;
    letter-spacing: 3px;
    text-transform: uppercase;
}

.tabs {
    display: flex;
    gap: 6px;
    margin: 36px 0 28px;
    flex-wrap: wrap;
    justify-content: center;
}
.tab-btn {
    background: var(--card);
    border: 1px solid var(--border);
    color: var(--muted);
    font-family: var(--sans);
    font-size: .78rem;
    font-weight: 600;
    letter-spacing: 1px;
    text-transform: uppercase;
    padding: 10px 18px;
    border-radius: 8px;
    cursor: pointer;
    transition: all .2s;
    display: flex;
    align-items: center;
    gap: 7px;
}
.tab-btn:hover { border-color: var(--accent); color: var(--accent); background: rgba(0,229,255,.06); }
.tab-btn.active {
    background: var(--accent);
    color: #0b0f19;
    border-color: var(--accent);
    font-weight: 700;
}
.tab-icon { font-size: 1rem; }

.panel { display: none; }
.panel.active { display: block; }

.card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 28px 28px 24px;
    margin-bottom: 20px;
    position: relative;
    overflow: hidden;
}
.card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, var(--accent), var(--accent3));
}
.card-title {
    font-size: 1.1rem;
    font-weight: 800;
    margin-bottom: 6px;
    display: flex;
    align-items: center;
    gap: 9px;
}
.card-desc {
    font-family: var(--mono);
    font-size: .72rem;
    color: var(--muted);
    margin-bottom: 22px;
    line-height: 1.6;
}

.field { margin-bottom: 18px; }
label {
    display: block;
    font-size: .75rem;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 7px;
    font-family: var(--mono);
}
input[type=text], input[type=number], textarea, select {
    width: 100%;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--text);
    font-family: var(--mono);
    font-size: .85rem;
    padding: 11px 14px;
    outline: none;
    transition: border-color .2s, box-shadow .2s;
    resize: vertical;
}
input:focus, textarea:focus, select:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(0,229,255,.12);
}
select option { background: var(--card); }
textarea { min-height: 90px; }
textarea.tall { min-height: 140px; }

.btn-row { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 4px; }
button[type=submit] {
    font-family: var(--sans);
    font-weight: 700;
    font-size: .82rem;
    letter-spacing: 1px;
    text-transform: uppercase;
    padding: 12px 24px;
    border: none;
    border-radius: 8px;
    cursor: pointer;
    transition: all .2s;
}
.btn-primary { background: var(--accent); color: #0b0f19; }
.btn-primary:hover { background: #00c8e0; transform: translateY(-1px); box-shadow: 0 4px 20px rgba(0,229,255,.3); }
.btn-danger  { background: var(--accent2); color: #fff; }
.btn-danger:hover  { background: #e55; transform: translateY(-1px); box-shadow: 0 4px 20px rgba(255,107,107,.3); }
.btn-success { background: var(--accent3); color: #111; }
.btn-success:hover { background: #8fee4a; transform: translateY(-1px); }
.btn-neutral { background: var(--border); color: var(--text); }
.btn-neutral:hover { background: #3a4f7a; }

.result-box {
    background: var(--surface);
    border: 1px solid var(--accent);
    border-radius: var(--radius);
    padding: 22px 24px;
    margin-top: 20px;
    animation: fadeSlide .35s ease;
}
@keyframes fadeSlide { from { opacity:0; transform: translateY(8px); } to { opacity:1; transform: translateY(0); } }
.result-box h3 {
    font-size: .72rem;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: var(--accent);
    font-family: var(--mono);
    margin-bottom: 14px;
    display: flex;
    align-items: center;
    gap: 7px;
}
.result-row { margin-bottom: 12px; }
.result-row label { color: var(--muted); margin-bottom: 4px; }
.result-val {
    font-family: var(--mono);
    font-size: .82rem;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 7px;
    padding: 10px 14px;
    word-break: break-all;
    line-height: 1.6;
    color: var(--accent3);
}
.result-val.big { font-size: .7rem; }
.valid   { color: var(--accent3) !important; font-weight: 700; }
.invalid { color: var(--accent2) !important; font-weight: 700; }

.error-box {
    background: rgba(255,107,107,.1);
    border: 1px solid var(--accent2);
    border-radius: var(--radius);
    padding: 14px 20px;
    margin-top: 18px;
    font-family: var(--mono);
    font-size: .82rem;
    color: var(--accent2);
    animation: fadeSlide .3s ease;
}

.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
@media (max-width: 600px) { .grid-2 { grid-template-columns: 1fr; } .tabs { gap: 4px; } .tab-btn { font-size: .7rem; padding: 8px 13px; } }

footer {
    text-align: center;
    padding: 28px 0 12px;
    font-family: var(--mono);
    font-size: .7rem;
    color: var(--muted);
    border-top: 1px solid var(--border);
    margin-top: 20px;
}
</style>
</head>
<body>
<div class="wrap">

<header>
    <div class="brand">🔐 Kripto<span>Lab</span></div>
    <div class="subtitle">Web Tools Kriptografi · Pertemuan 1–7</div>
</header>

<!-- Tab Navigation -->
<nav class="tabs" id="tabNav">
    <button class="tab-btn <?= $activeTab==='caesar'?'active':'' ?>" onclick="switchTab('caesar',this)">
        <span class="tab-icon">🔄</span>Caesar Cipher
    </button>
    <button class="tab-btn <?= $activeTab==='xor'?'active':'' ?>" onclick="switchTab('xor',this)">
        <span class="tab-icon">⊕</span>XOR Cipher
    </button>
    <button class="tab-btn <?= $activeTab==='sha256'?'active':'' ?>" onclick="switchTab('sha256',this)">
        <span class="tab-icon">#</span>SHA-256
    </button>
    <button class="tab-btn <?= $activeTab==='rsa'?'active':'' ?>" onclick="switchTab('rsa',this)">
        <span class="tab-icon">🗝</span>RSA
    </button>
    <button class="tab-btn <?= $activeTab==='sig'?'active':'' ?>" onclick="switchTab('sig',this)">
        <span class="tab-icon">✍️</span>Digital Signature
    </button>
</nav>

<!-- PANEL 1 - CAESAR CIPHER -->
<div id="panel-caesar" class="panel <?= $activeTab==='caesar'?'active':'' ?>">
    <div class="card">
        <div class="card-title">🔄 Caesar Cipher</div>
        <div class="card-desc">
            Substitusi klasik: setiap huruf digeser sejumlah <em>n</em> posisi dalam alfabet.<br>
            ROT-13 adalah Caesar dengan shift = 13. Hanya mengubah huruf A–Z, karakter lain diabaikan.
        </div>
        <form method="POST" action="">
            <input type="hidden" name="action" id="caesar_action" value="caesar_encrypt">
            <div class="field">
                <label>Teks Input</label>
                <textarea name="caesar_text" placeholder="Ketikkan teks di sini..."><?= h($_POST['caesar_text'] ?? '') ?></textarea>
            </div>
            <div class="field" style="max-width:200px">
                <label>Shift (0–25)</label>
                <input type="number" name="caesar_shift" min="0" max="25" value="<?= h($_POST['caesar_shift'] ?? '3') ?>">
            </div>
            <div class="btn-row">
                <button type="submit" class="btn-primary" onclick="document.getElementById('caesar_action').value='caesar_encrypt'">🔒 Enkripsi</button>
                <button type="submit" class="btn-danger"  onclick="document.getElementById('caesar_action').value='caesar_decrypt'">🔓 Dekripsi</button>
            </div>
        </form>
    </div>

    <?php if ($result && $result['tool']==='Caesar Cipher'): ?>
    <div class="result-box">
        <h3>⚡ Hasil — <?= h($result['op']) ?></h3>
        <div class="grid-2">
            <div class="result-row">
                <label>Input</label>
                <div class="result-val"><?= h($result['input']) ?></div>
            </div>
            <div class="result-row">
                <label>Shift Efektif</label>
                <div class="result-val"><?= $result['shift'] ?></div>
            </div>
        </div>
        <div class="result-row">
            <label>Output</label>
            <div class="result-val"><?= h($result['out']) ?></div>
        </div>
    </div>
    <?php endif; ?>
    <?php if ($error && $activeTab==='caesar'): ?>
        <div class="error-box">⚠️ <?= h($error) ?></div>
    <?php endif; ?>
</div>

<!-- PANEL 2 - XOR CIPHER -->
<div id="panel-xor" class="panel <?= $activeTab==='xor'?'active':'' ?>">
    <div class="card">
        <div class="card-title">⊕ XOR Cipher</div>
        <div class="card-desc">
            Setiap byte teks di-XOR dengan byte kunci secara bergantian (repeating key).<br>
            Enkripsi → output dalam format <strong>HEX</strong>. Dekripsi → input wajib berupa string HEX.
        </div>
        <form method="POST" action="">
            <input type="hidden" name="action" id="xor_action" value="xor_encrypt">
            <div class="field">
                <label>Teks / HEX Input</label>
                <textarea name="xor_text" placeholder="Enkripsi: teks biasa | Dekripsi: hex string"><?= h($_POST['xor_text'] ?? '') ?></textarea>
            </div>
            <div class="field">
                <label>Kunci (Key)</label>
                <input type="text" name="xor_key" placeholder="Contoh: secret123" value="<?= h($_POST['xor_key'] ?? '') ?>">
            </div>
            <div class="btn-row">
                <button type="submit" class="btn-primary" onclick="document.getElementById('xor_action').value='xor_encrypt'">🔒 Enkripsi → HEX</button>
                <button type="submit" class="btn-danger"  onclick="document.getElementById('xor_action').value='xor_decrypt'">🔓 Dekripsi HEX</button>
            </div>
        </form>
    </div>

    <?php if ($result && $result['tool']==='XOR Cipher'): ?>
    <div class="result-box">
        <h3>⚡ Hasil — <?= h($result['op']) ?></h3>
        <div class="grid-2">
            <div class="result-row">
                <label>Input</label>
                <div class="result-val"><?= h($result['input']) ?></div>
            </div>
            <div class="result-row">
                <label>Kunci</label>
                <div class="result-val"><?= h($result['key']) ?></div>
            </div>
        </div>
        <div class="result-row">
            <label>Output</label>
            <div class="result-val"><?= h($result['out']) ?></div>
        </div>
    </div>
    <?php endif; ?>
    <?php if ($error && $activeTab==='xor'): ?>
        <div class="error-box">⚠️ <?= h($error) ?></div>
    <?php endif; ?>
</div>

<!-- PANEL 3 - SHA-256 -->
<div id="panel-sha256" class="panel <?= $activeTab==='sha256'?'active':'' ?>">
    <div class="card">
        <div class="card-title"># SHA-256 Hashing</div>
        <div class="card-desc">
            SHA-256 adalah fungsi hash kriptografis satu arah (one-way). Input sepanjang apapun menghasilkan digest 256-bit (64 karakter hex) yang unik. Digunakan untuk verifikasi integritas data, penyimpanan password, dan blockchain.
        </div>
        <form method="POST" action="">
            <input type="hidden" name="action" value="sha256">
            <div class="field">
                <label>Teks / Data yang akan di-hash</label>
                <textarea name="sha_text" placeholder="Ketikkan teks apapun..."><?= h($_POST['sha_text'] ?? '') ?></textarea>
            </div>
            <div class="btn-row">
                <button type="submit" class="btn-primary">🔑 Generate Hash SHA-256</button>
            </div>
        </form>
    </div>

    <?php if ($result && $result['tool']==='SHA-256'): ?>
    <div class="result-box">
        <h3>⚡ Hash Digest</h3>
        <div class="result-row">
            <label>Input</label>
            <div class="result-val"><?= h($result['input']) ?></div>
        </div>
        <div class="result-row">
            <label>SHA-256 Digest (Hex)</label>
            <div class="result-val"><?= h($result['out']) ?></div>
        </div>
        <div class="result-row">
            <label>Ukuran Output</label>
            <div class="result-val"><?= h($result['len']) ?></div>
        </div>
    </div>
    <?php endif; ?>
</div>

<!-- PANEL 4 - RSA -->
<div id="panel-rsa" class="panel <?= $activeTab==='rsa'?'active':'' ?>">

    <div class="card">
        <div class="card-title">🗝 RSA — Generate Key Pair</div>
        <div class="card-desc">
            Menggunakan fungsi OpenSSL PHP. Generate private key + public key. Private key JANGAN disebarkan!
        </div>
        <form method="POST" action="">
            <input type="hidden" name="action" value="rsa_generate">
            <div class="field" style="max-width:220px">
                <label>Ukuran Kunci (bits)</label>
                <select name="rsa_bits">
                    <option value="1024" <?= (($_POST['rsa_bits']??'2048')==='1024')?'selected':'' ?>>1024 bit (cepat, kurang aman)</option>
                    <option value="2048" <?= (($_POST['rsa_bits']??'2048')==='2048')?'selected':'' ?>>2048 bit (standar)</option>
                    <option value="4096" <?= (($_POST['rsa_bits']??'2048')==='4096')?'selected':'' ?>>4096 bit (lambat, sangat aman)</option>
                </select>
            </div>
            <div class="btn-row">
                <button type="submit" class="btn-primary">⚙️ Generate Key Pair</button>
            </div>
        </form>
    </div>

    <?php if ($result && $result['tool']==='RSA' && $result['op']==='Generate Key Pair'): ?>
    <div class="result-box">
        <h3>⚡ Key Pair Berhasil Dibuat (<?= $result['bits'] ?> bit)</h3>
        <div class="result-row">
            <label>Private Key (simpan di SESSION otomatis)</label>
            <div class="result-val big"><?= h($result['priv']) ?></div>
        </div>
        <div class="result-row">
            <label>Public Key</label>
            <div class="result-val big"><?= h($result['pub']) ?></div>
        </div>
    </div>
    <?php endif; ?>

    <div class="card" style="margin-top:20px">
        <div class="card-title" style="font-size:.95rem">🔒 RSA Enkripsi / Dekripsi</div>
        <div class="card-desc">
            Enkripsi menggunakan Public Key. Dekripsi menggunakan Private Key.<br>
            Jika sudah generate di atas, kunci tersimpan di session otomatis (kosongkan field = pakai session).
        </div>

        <div class="grid-2">
            <!-- Form Enkripsi -->
            <form method="POST" action="">
                <input type="hidden" name="action" value="rsa_encrypt">
                <div class="field">
                    <label>Pesan (maks ~190 byte utk 2048-bit)</label>
                    <textarea name="rsa_plain" placeholder="Teks yang akan dienkripsi"><?= h($_POST['rsa_plain'] ?? '') ?></textarea>
                </div>
                <div class="field">
                    <label>Public Key (opsional, kosong = pakai session)</label>
                    <textarea name="rsa_pub_key" class="tall" placeholder="-----BEGIN PUBLIC KEY-----&#10;...&#10;-----END PUBLIC KEY-----"><?= h($_POST['rsa_pub_key'] ?? '') ?></textarea>
                </div>
                <button type="submit" class="btn-primary">🔒 Enkripsi</button>
            </form>
            <!-- Form Dekripsi -->
            <form method="POST" action="">
                <input type="hidden" name="action" value="rsa_decrypt">
                <div class="field">
                    <label>Ciphertext (Base64)</label>
                    <textarea name="rsa_cipher" placeholder="Paste hasil enkripsi (Base64)"><?= h($_POST['rsa_cipher'] ?? '') ?></textarea>
                </div>
                <div class="field">
                    <label>Private Key (opsional, kosong = pakai session)</label>
                    <textarea name="rsa_priv_key" class="tall" placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"><?= h($_POST['rsa_priv_key'] ?? '') ?></textarea>
                </div>
                <button type="submit" class="btn-danger">🔓 Dekripsi</button>
            </form>
        </div>
    </div>

    <?php if ($result && $result['tool']==='RSA' && in_array($result['op'], ['Enkripsi','Dekripsi'])): ?>
    <div class="result-box">
        <h3>⚡ Hasil — RSA <?= h($result['op']) ?></h3>
        <div class="result-row">
            <label>Input</label>
            <div class="result-val big"><?= h($result['input']) ?></div>
        </div>
        <div class="result-row">
            <label>Output</label>
            <div class="result-val big"><?= h($result['out']) ?></div>
        </div>
    </div>
    <?php endif; ?>
    <?php if ($error && $activeTab==='rsa'): ?>
        <div class="error-box">⚠️ <?= h($error) ?></div>
    <?php endif; ?>
</div>

<!-- PANEL 5 - DIGITAL SIGNATURE -->
<div id="panel-sig" class="panel <?= $activeTab==='sig'?'active':'' ?>">

    <div class="card">
        <div class="card-title">✍️ Digital Signature — Generate Key</div>
        <div class="card-desc">
            Tanda tangan digital membuktikan <strong>keaslian</strong> dan <strong>integritas</strong> dokumen.<br>
            Sign menggunakan Private Key → Verify menggunakan Public Key (OPENSSL_ALGO_SHA256).
        </div>
        <form method="POST" action="">
            <input type="hidden" name="action" value="sig_generate_key">
            <div class="btn-row">
                <button type="submit" class="btn-neutral">⚙️ Generate Key Pair untuk Tanda Tangan</button>
            </div>
        </form>
    </div>

    <?php if ($result && $result['tool']==='Digital Signature' && $result['op']==='Generate Key'): ?>
    <div class="result-box">
        <h3>⚡ Key Pair Tanda Tangan Dibuat</h3>
        <div class="result-row"><label>Private Key (Sign)</label><div class="result-val big"><?= h($result['priv']) ?></div></div>
        <div class="result-row"><label>Public Key (Verify)</label><div class="result-val big"><?= h($result['pub']) ?></div></div>
    </div>
    <?php endif; ?>

    <div class="grid-2" style="margin-top:20px">
        <!-- Form Sign -->
        <div class="card">
            <div class="card-title" style="font-size:.9rem">🖊 Sign Dokumen</div>
            <form method="POST" action="">
                <input type="hidden" name="action" value="sig_sign">
                <div class="field">
                    <label>Isi Dokumen</label>
                    <textarea name="sig_doc" placeholder="Teks dokumen yang akan ditandatangani"><?= h($_POST['sig_doc'] ?? '') ?></textarea>
                </div>
                <div class="field">
                    <label>Private Key (kosong = pakai session)</label>
                    <textarea name="sig_priv_key" placeholder="-----BEGIN PRIVATE KEY-----"><?= h($_POST['sig_priv_key'] ?? '') ?></textarea>
                </div>
                <button type="submit" class="btn-primary">✍️ Sign</button>
            </form>
        </div>
        <!-- Form Verify -->
        <div class="card">
            <div class="card-title" style="font-size:.9rem">🔍 Verify Tanda Tangan</div>
            <form method="POST" action="">
                <input type="hidden" name="action" value="sig_verify">
                <div class="field">
                    <label>Isi Dokumen</label>
                    <textarea name="sig_doc_v" placeholder="Teks dokumen asli"><?= h($_POST['sig_doc_v'] ?? '') ?></textarea>
                </div>
                <div class="field">
                    <label>Tanda Tangan (Base64)</label>
                    <textarea name="sig_sig_v" placeholder="Paste tanda tangan di sini"><?= h($_POST['sig_sig_v'] ?? '') ?></textarea>
                </div>
                <div class="field">
                    <label>Public Key (kosong = pakai session)</label>
                    <textarea name="sig_pub_key" placeholder="-----BEGIN PUBLIC KEY-----"><?= h($_POST['sig_pub_key'] ?? '') ?></textarea>
                </div>
                <button type="submit" class="btn-success">✅ Verify</button>
            </form>
        </div>
    </div>

    <?php if ($result && $result['tool']==='Digital Signature' && $result['op']==='Sign'): ?>
    <div class="result-box">
        <h3>⚡ Tanda Tangan Dibuat</h3>
        <div class="result-row"><label>Dokumen</label><div class="result-val"><?= h($result['doc']) ?></div></div>
        <div class="result-row"><label>Tanda Tangan (Base64) — copy untuk Verify</label><div class="result-val big"><?= h($result['sig']) ?></div></div>
    </div>
    <?php endif; ?>

    <?php if ($result && $result['tool']==='Digital Signature' && $result['op']==='Verify'): ?>
    <div class="result-box">
        <h3>⚡ Hasil Verifikasi</h3>
        <div class="result-row"><label>Dokumen</label><div class="result-val"><?= h($result['doc']) ?></div></div>
        <div class="result-row">
            <label>Status</label>
            <div class="result-val <?= $result['ok'] ? 'valid' : 'invalid' ?>"><?= h($result['status']) ?></div>
        </div>
    </div>
    <?php endif; ?>

    <?php if ($error && $activeTab==='sig'): ?>
        <div class="error-box">⚠️ <?= h($error) ?></div>
    <?php endif; ?>
</div>

<footer>
    KriptoLab · Single File PHP Application · UTS Kriptografi · Pertemuan 1–7<br>
    Caesar · XOR · SHA-256 · RSA · Digital Signature
</footer>

</div><!-- /wrap -->

<script>
function switchTab(name, btn) {
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById('panel-' + name).classList.add('active');
    btn.classList.add('active');
}
</script>
</body>
</html>
