<?php
/**
 * Aplikasi Kripto RSA Asimetris
 * Memenuhi modul praktikum: Generate Key, Enkripsi Publik, Dekripsi Privat.
 */

$action = $_POST['action'] ?? 'encrypt'; // Default action is encrypt
if (isset($_POST['reset'])) {
    $action = 'encrypt';
    $input_text = '';
    $input_key = '';
} else {
    $input_text = $_POST['input_text'] ?? '';
    $input_key = $_POST['input_key'] ?? '';
}

$hasil_teks = '';
$public_key_out = '';
$private_key_out = '';
$success_msg = '';

// Fungsi untuk Pembangkitan Kunci RSA 2048-bit
function generate_rsa_keys() {
    $config = array(
        "digest_alg" => "sha512",
        "private_key_bits" => 2048,
        "private_key_type" => OPENSSL_KEYTYPE_RSA,
    );
    
    $res = openssl_pkey_new($config);
    
    // Workaround Laragon OpenSSL conf
    if (!$res) {
        $laragon_apache_path = 'C:/laragon/bin/apache';
        if (is_dir($laragon_apache_path)) {
            $apache_dirs = glob($laragon_apache_path . '/*', GLOB_ONLYDIR);
            foreach ($apache_dirs as $dir) {
                $conf_path = $dir . '/conf/openssl.cnf';
                if (file_exists($conf_path)) {
                    $config['config'] = $conf_path; 
                    $res = openssl_pkey_new($config);
                    if ($res) break; 
                }
            }
        }
    }
    
    if (!$res) {
        return ["error" => "Gagal membangkitkan kunci. Pastikan ekstensi OpenSSL aktif (cek php.ini)."];
    }
    
    openssl_pkey_export($res, $privKey, null, $config);
    $pubKeyDetails = openssl_pkey_get_details($res);
    $pubKey = $pubKeyDetails["key"];
    
    return [
        "private" => $privKey,
        "public" => $pubKey
    ];
}

// Kontrol Alur Eksekusi
if ($_SERVER["REQUEST_METHOD"] == "POST" && !isset($_POST['reset'])) {
    if ($action === 'generate') {
        $keys = generate_rsa_keys();
        if (isset($keys['error'])) {
            $hasil_teks = "ERROR: " . $keys['error'];
        } else {
            $public_key_out = $keys['public'];
            $private_key_out = $keys['private'];
            $success_msg = "Kunci RSA berhasil dibuat! Silakan salin kunci di bawah ini.";
        }
    } elseif ($action === 'encrypt') {
        if (empty($input_text) || empty($input_key)) {
            $hasil_teks = "ERROR: Pesan Asli dan Public Key wajib diisi.";
        } else {
            $success = @openssl_public_encrypt($input_text, $encrypted, $input_key);
            if ($success) {
                $hasil_teks = base64_encode($encrypted);
                $success_msg = "Enkripsi berhasil!";
            } else {
                $hasil_teks = "ERROR: Gagal enkripsi. Pastikan Kunci yang dimasukkan adalah PUBLIC KEY yang valid.";
            }
        }
    } elseif ($action === 'decrypt') {
        if (empty($input_text) || empty($input_key)) {
            $hasil_teks = "ERROR: Teks Sandi dan Private Key wajib diisi.";
        } else {
            $decoded_text = base64_decode($input_text);
            $success = @openssl_private_decrypt($decoded_text, $decrypted, $input_key);
            if ($success) {
                $hasil_teks = $decrypted;
                $success_msg = "Dekripsi berhasil!";
            } else {
                $hasil_teks = "ERROR: Gagal dekripsi. Pastikan Kunci yang dimasukkan adalah PRIVATE KEY yang tepat.";
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RSA Kriptografi</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="styles/style.css">
</head>
<body>

    <main class="container">
        <header class="header">
            <h1>RSA Kriptografi</h1>
            <p>Implementasi Enkripsi & Dekripsi Asimetris</p>
        </header>

        <section class="card">
            <div class="guide-box">
                <span>Panduan Penggunaan:</span> Silakan pilih menu di bawah ini. Untuk enkripsi/dekripsi, pastikan Anda memasukkan pasangan kunci yang tepat (Public Key untuk Enkripsi, Private Key untuk Dekripsi).
            </div>

            <!-- Form Enctype diperlukan agar Base64 tanda "+" tidak hilang -->
            <form method="POST" action="" id="rsa_form" enctype="multipart/form-data">
                
                <!-- Pilihan Aksi (Menggantikan banyak tombol Submit) -->
                <div class="action-selector">
                    <label>
                        <input type="radio" name="action" value="generate" <?php if($action=='generate') echo 'checked'; ?>>
                        <span>Generate Key</span>
                    </label>
                    <label>
                        <input type="radio" name="action" value="encrypt" <?php if($action=='encrypt') echo 'checked'; ?>>
                        <span>Enkripsi</span>
                    </label>
                    <label>
                        <input type="radio" name="action" value="decrypt" <?php if($action=='decrypt') echo 'checked'; ?>>
                        <span>Dekripsi</span>
                    </label>
                </div>

                <div class="form-group" id="group_pesan">
                    <label id="label_pesan">Pesan Asli (Plaintext)</label>
                    <textarea name="input_text" id="input_text" placeholder="Ketik pesan..."><?php echo htmlspecialchars($input_text); ?></textarea>
                </div>

                <div class="form-group" id="group_key">
                    <label id="label_key">Public Key (Untuk Enkripsi)</label>
                    <textarea name="input_key" id="input_key" class="key-input" placeholder="Paste kunci di sini..."><?php echo htmlspecialchars($input_key); ?></textarea>
                </div>

                <div class="btn-container">
                    <button type="submit" class="btn-primary" id="btn_submit">Proses Eksekusi</button>
                    <button type="submit" name="reset" value="1" class="btn-reset" formnovalidate>Reset Form</button>
                </div>
            </form>

            <?php if ($_SERVER["REQUEST_METHOD"] == "POST" && !isset($_POST['reset'])): ?>
            <div class="result-panel" id="result_section">
                
                <?php if (!empty($success_msg)): ?>
                    <div class="alert alert-success"><?php echo $success_msg; ?></div>
                <?php endif; ?>
                
                <?php if (strpos($hasil_teks, 'ERROR') !== false): ?>
                    <div class="alert alert-error"><?php echo htmlspecialchars($hasil_teks); ?></div>
                <?php endif; ?>

                <?php if ($action === 'generate' && empty($keys['error'])): ?>
                    <div class="result-box-wrapper">
                        <div class="result-header">
                            <span class="result-label" style="color: #007bff;">PUBLIC KEY</span>
                            <button type="button" class="btn-copy" onclick="copyText('pub_key_out')">Salin Public Key</button>
                        </div>
                        <div class="result-box" id="pub_key_out" style="color: #007bff; border-color: #007bff;"><?php echo htmlspecialchars($public_key_out); ?></div>
                    </div>
                    
                    <div class="result-box-wrapper">
                        <div class="result-header">
                            <span class="result-label" style="color: #ff0000;">PRIVATE KEY</span>
                            <button type="button" class="btn-copy" onclick="copyText('priv_key_out')">Salin Private Key</button>
                        </div>
                        <div class="result-box" id="priv_key_out" style="color: #ff0000; border-color: #ff0000;"><?php echo htmlspecialchars($private_key_out); ?></div>
                    </div>

                <?php elseif ($action !== 'generate' && strpos($hasil_teks, 'ERROR') === false): ?>
                    <div class="result-box-wrapper">
                        <div class="result-header">
                            <span class="result-label">HASIL <?php echo strtoupper($action); ?></span>
                            <button type="button" class="btn-copy" onclick="copyText('general_out')">Salin Hasil</button>
                        </div>
                        <div class="result-box" id="general_out"><?php echo htmlspecialchars($hasil_teks); ?></div>
                    </div>
                <?php endif; ?>

            </div>
            <script>
                // Auto scroll ke hasil jika ada proses submit
                document.getElementById('result_section').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            </script>
            <?php endif; ?>

        </section>

        <footer class="footer">
            <h3>Mohammad Dimas Al Fateh</h3>
            <p class="subtitle">Tugas 5</p>
            
            <div class="social-links">
                <a href="https://github.com/xzdmasz" target="_blank" aria-label="GitHub">
                    <svg viewBox="0 0 24 24"><path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg>
                </a>
                <a href="https://www.linkedin.com/in/alpateeh" target="_blank" aria-label="LinkedIn">
                    <svg viewBox="0 0 24 24"><path d="M19 0h-14c-2.761 0-5 2.239-5 5v14c0 2.761 2.239 5 5 5h14c2.762 0 5-2.239 5-5v-14c0-2.761-2.238-5-5-5zm-11 19h-3v-11h3v11zm-1.5-12.268c-.966 0-1.75-.79-1.75-1.764s.784-1.764 1.75-1.764 1.75.79 1.75 1.764-.783 1.764-1.75 1.764zm13.5 12.268h-3v-5.604c0-3.368-4-3.113-4 0v5.604h-3v-11h3v1.765c1.396-2.586 7-2.777 7 2.476v6.759z"/></svg>
                </a>
                <a href="https://www.instagram.com/alpateeh_?igsh=MWd0Nmhmdmdnanoxbw==" target="_blank" aria-label="Instagram">
                    <svg viewBox="0 0 24 24"><path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zm0-2.163c-3.259 0-3.667.014-4.947.072-4.358.2-6.78 2.618-6.98 6.98-.059 1.281-.073 1.689-.073 4.948 0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98 1.281.058 1.689.072 4.948.072 3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98-1.281-.059-1.69-.073-4.949-.073zm0 5.838c-3.403 0-6.162 2.759-6.162 6.162s2.759 6.163 6.162 6.163 6.162-2.759 6.162-6.163-2.759-6.162-6.162-6.162zm0 10.162c-2.209 0-4-1.79-4-4 0-2.209 1.791-4 4-4s4 1.791 4 4c0 2.21-1.791 4-4 4zm6.406-11.845c-.796 0-1.441.645-1.441 1.44s.645 1.44 1.441 1.44c.795 0 1.439-.645 1.439-1.44s-.644-1.44-1.439-1.44z"/></svg>
                </a>
            </div>
            
            <p class="copyright">© 2026 Mohammad Dimas Al Fateh. All rights reserved.</p>
        </footer>
    </main>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const radios = document.querySelectorAll('input[name="action"]');
            const groupPesan = document.getElementById('group_pesan');
            const groupKey = document.getElementById('group_key');
            const labelPesan = document.getElementById('label_pesan');
            const labelKey = document.getElementById('label_key');
            const inputPesan = document.getElementById('input_text');
            const inputKey = document.getElementById('input_key');
            const btnSubmit = document.getElementById('btn_submit');

            function updateUI() {
                // Cari radio button yang sedang aktif
                const action = document.querySelector('input[name="action"]:checked').value;
                
                if (action === 'generate') {
                    // Sembunyikan form input saat mode Generate Key
                    groupPesan.style.display = 'none';
                    groupKey.style.display = 'none';
                    inputPesan.required = false;
                    inputKey.required = false;
                    btnSubmit.textContent = 'Generate Key Pair';
                } else if (action === 'encrypt') {
                    // Tampilkan form untuk Enkripsi
                    groupPesan.style.display = 'block';
                    groupKey.style.display = 'block';
                    labelPesan.textContent = 'Pesan Asli (Plaintext)';
                    labelKey.textContent = 'Public Key (Untuk Enkripsi)';
                    inputPesan.placeholder = 'Ketik pesan rahasia yang ingin dienkripsi...';
                    inputKey.placeholder = 'Paste -----BEGIN PUBLIC KEY----- di sini...';
                    inputPesan.required = true;
                    inputKey.required = true;
                    btnSubmit.textContent = 'Proses Enkripsi';
                } else if (action === 'decrypt') {
                    // Tampilkan form untuk Dekripsi
                    groupPesan.style.display = 'block';
                    groupKey.style.display = 'block';
                    labelPesan.textContent = 'Teks Sandi (Ciphertext)';
                    labelKey.textContent = 'Private Key (Untuk Dekripsi)';
                    inputPesan.placeholder = 'Paste teks sandi (hasil enkripsi) di sini...';
                    inputKey.placeholder = 'Paste -----BEGIN PRIVATE KEY----- di sini...';
                    inputPesan.required = true;
                    inputKey.required = true;
                    btnSubmit.textContent = 'Proses Dekripsi';
                }
            }

            // Event listener saat user ganti tab
            radios.forEach(radio => radio.addEventListener('change', function() {
                updateUI();
            }));
            
            // Inisialisasi UI saat pertama load
            updateUI();
        });

        // Fungsi copy to clipboard
        function copyText(elementId) {
            const el = document.getElementById(elementId);
            if (!el) return;
            
            const textarea = document.createElement('textarea');
            textarea.value = el.innerText;
            document.body.appendChild(textarea);
            textarea.select();
            
            try {
                document.execCommand('copy');
                alert('Berhasil disalin ke clipboard!');
            } catch (err) {
                alert('Gagal menyalin teks.');
            }
            
            document.body.removeChild(textarea);
        }
    </script>
</body>
</html>
