/**
 * SecureVault - Logic v3 (Key Wrapping & Recovery)
 */

class SecurityAnalyzer {
    static analyze(password) {
        if (!password) return "weak";
        let score = 0;
        if (password.length >= 8) score++;
        if (password.length >= 12) score++;
        if (/[A-Z]/.test(password)) score++;
        if (/[0-9]/.test(password)) score++;
        if (/[^A-Za-z0-9]/.test(password)) score++;
        if (score < 3) return "weak";
        if (score < 5) return "medium";
        return "strong";
    }

    static checkReuse(password, entries, currentId = null) {
        return entries.some(e => e.password === password && e.id !== currentId);
    }
}

class CryptoManager {
    constructor() {
        this.algo = "AES-GCM";
        this.kdf = "PBKDF2";
        this.hash = "SHA-256";
        this.iterations = 100000;
    }

    /* --- PRIMITIVES --- */
    generateSalt() { return window.crypto.getRandomValues(new Uint8Array(16)); }
    generateIV() { return window.crypto.getRandomValues(new Uint8Array(12)); }

    // Generate the Master Vault Key (VK) - Random 256-bit key
    async generateVaultKey() {
        return window.crypto.subtle.generateKey(
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    }

    // Derive a Wrapping Key (UK or RK) from Input (Password or Recovery Code)
    async deriveWrappingKey(inputString, salt) {
        const enc = new TextEncoder();
        const keyMaterial = await window.crypto.subtle.importKey(
            "raw", enc.encode(inputString), { name: "PBKDF2" }, false, ["deriveKey"]
        );
        return window.crypto.subtle.deriveKey(
            { name: "PBKDF2", salt: salt, iterations: this.iterations, hash: this.hash },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            true, // Extractable so we can use it to unwrap
            ["wrapKey", "unwrapKey", "encrypt", "decrypt"]
        );
    }

    /* --- AES KEY WRAPPING --- */

    // Wrap the Vault Key with a Wrapping Key (e.g., wrap VK with UK)
    async wrapKey(keyToWrap, wrappingKey) {
        const iv = this.generateIV();
        const wrappedBuffer = await window.crypto.subtle.wrapKey(
            "raw",
            keyToWrap,
            wrappingKey,
            { name: "AES-GCM", iv: iv }
        );
        return { iv, ciphertext: wrappedBuffer };
    }

    // Unwrap the Vault Key using a Wrapping Key
    async unwrapKey(wrappedBuffer, wrappingKey, iv) {
        return window.crypto.subtle.unwrapKey(
            "raw",
            wrappedBuffer,
            wrappingKey,
            { name: "AES-GCM", iv: iv },
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    }

    /* --- DATA ENCRYPTION --- */

    // Encrypt data with the Vault Key
    async encryptData(data, vaultKey) {
        const enc = new TextEncoder();
        const iv = this.generateIV();
        const encodedData = enc.encode(JSON.stringify(data));
        const ciphertext = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv }, vaultKey, encodedData
        );
        return { iv, ciphertext };
    }

    // Decrypt data with the Vault Key
    async decryptData(ciphertext, iv, vaultKey) {
        try {
            const decrypted = await window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv }, vaultKey, ciphertext
            );
            const dec = new TextDecoder();
            return JSON.parse(dec.decode(decrypted));
        } catch (e) {
            throw new Error("Déchiffrement échoué.");
        }
    }

    /* --- HELPERS --- */
    generateRecoveryCode() {
        // Format: XXXX-XXXX-XXXX-XXXX
        const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // No I, 1, O, 0 for clarity
        let code = "";
        const bytes = new Uint8Array(16);
        window.crypto.getRandomValues(bytes);
        for (let i = 0; i < 16; i++) {
            code += chars[bytes[i] % chars.length];
            if ((i + 1) % 4 === 0 && i !== 15) code += "-";
        }
        return code;
    }

    bufferToBase64(buffer) { return btoa(String.fromCharCode(...new Uint8Array(buffer))); }
    base64ToBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes.buffer;
    }
    uint8ToBase64(u8) { return this.bufferToBase64(u8.buffer); }
}

class StorageManager {
    static get STORE_KEY() { return "secure_vault_data_v3"; }

    // Save the entire vault state
    save(payload) {
        // Payload expects: {
        //   salt: Base64,
        //   wrappedUserKey: { iv: Base64, data: Base64 },
        //   wrappedRecoveryKey: { iv: Base64, data: Base64 },
        //   vaultData: { iv: Base64, data: Base64 }
        // }
        payload.version = 3;
        localStorage.setItem(StorageManager.STORE_KEY, JSON.stringify(payload));
    }

    load() {
        const raw = localStorage.getItem(StorageManager.STORE_KEY);
        // Fallback or migration check could go here
        if (!raw) return null;
        return JSON.parse(raw);
    }

    exists() { return localStorage.getItem(StorageManager.STORE_KEY) !== null; }

    // For manual export
    exportData() {
        const raw = localStorage.getItem(StorageManager.STORE_KEY);
        if (!raw) return null;
        return new Blob([raw], { type: "application/json" });
    }

    importData(jsonString) {
        try {
            const parsed = JSON.parse(jsonString);
            if (!parsed.version && !parsed.iv) throw new Error("Format inconnu");

            // Basic validation
            if (parsed.version === 3 && (!parsed.wrappedUserKey || !parsed.vaultData)) {
                throw new Error("Données v3 corrompues");
            }

            localStorage.setItem(StorageManager.STORE_KEY, jsonString);
            return true;
        } catch (e) {
            console.error(e);
            return false;
        }
    }

    clear() {
        localStorage.removeItem(StorageManager.STORE_KEY);
    }
}

class UIManager {
    constructor() {
        this.vaultKey = null; // The decrypted master key
        this.entries = [];
        this.currentRecoveryCode = null; // Only available during creation
        this.inactivityTimer = null;
        this.isDiscrete = false;

        // DOM Elements
        this.authSection = document.getElementById("auth-section");
        this.dashboardSection = document.getElementById("dashboard-section");
        this.recoveryInitSection = document.getElementById("recovery-init-section");
        this.recoveryFlowSection = document.getElementById("recovery-flow-section");

        this.masterPasswordInput = document.getElementById("master-password");
        this.entriesList = document.getElementById("entries-list");
        this.modal = document.getElementById("entry-modal");
        this.notificationArea = document.getElementById("notification-area");

        this.initEventListeners();
        this.checkInitialState();
    }

    checkInitialState() {
        if (storageManager.exists()) {
            document.getElementById("unlock-btn").textContent = "Déverrouiller";
            document.getElementById("auth-section").querySelector(".subtitle").textContent = "Entrez votre mot de passe pour accéder à vos données.";
            document.getElementById("forgot-password-link").classList.remove("hidden");
            document.getElementById("reset-vault-btn").classList.remove("hidden");
        } else {
            document.getElementById("unlock-btn").textContent = "Créer un nouveau coffre";
            document.getElementById("auth-section").querySelector(".subtitle").textContent = "Nouveau ici ? Créez un mot de passe maître.";
            document.getElementById("forgot-password-link").classList.add("hidden");
            document.getElementById("reset-vault-btn").classList.add("hidden");
        }
    }

    initEventListeners() {
        // --- AUTH ---
        document.getElementById("unlock-btn").addEventListener("click", () => this.handleUnlock());
        this.masterPasswordInput.addEventListener("keypress", (e) => { if (e.key === "Enter") this.handleUnlock(); });
        
        document.getElementById("reset-vault-btn").addEventListener("click", () => {
             if(confirm("ATTENTION : Cela va SUPPRIMER définitivement votre coffre actuel et toutes ses données.\n\nÊtes-vous sûr de vouloir tout effacer pour recommencer à zéro ?")) {
                 storageManager.clear();
                 location.reload();
             }
        });

        document.getElementById("forgot-password-link").addEventListener("click", (e) => {
            e.preventDefault();
            this.showRecoveryFlow();
        });

        // --- RECOVERY INIT (Creation) ---
        document.getElementById("copy-recovery-btn").addEventListener("click", () => {
            navigator.clipboard.writeText(this.currentRecoveryCode);
            this.showNotification("Code copié !");
        });
        document.getElementById("confirm-recovery-saved-btn").addEventListener("click", () => {
            this.transitionToDashboard();
        });

        // --- RECOVERY FLOW (Forgot Password) ---
        document.getElementById("recover-verify-btn").addEventListener("click", () => this.handleRecoveryVerify());
        document.getElementById("recover-reset-btn").addEventListener("click", () => this.handleRecoveryReset());
        document.getElementById("cancel-recovery-btn").addEventListener("click", () => {
            location.reload();
        });

        // --- DASHBOARD ACTIONS ---
        document.getElementById("lock-btn").addEventListener("click", () => location.reload());

        document.getElementById("show-recovery-btn").addEventListener("click", () => {
            alert("Pour des raisons de sécurité, nous ne stockons pas votre code de secours en clair.\n\nSi vous l'avez perdu mais que vous avez toujours votre mot de passe, le mieux est d'EXPORTER vos données, puis de recréer un coffre plus tard.");
        });

        document.getElementById("export-btn").addEventListener("click", () => {
            const blob = storageManager.exportData();
            if (blob) {
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = "securevault_keywrapped_backup.json";
                a.click();
            }
        });

        document.getElementById("import-btn").addEventListener("click", () => document.getElementById("import-file").click());
        document.getElementById("import-file").addEventListener("change", (e) => {
            const file = e.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (evt) => {
                if (confirm("Importer supprimera les données actuelles. Continuer ?")) {
                    if (storageManager.importData(evt.target.result)) {
                        alert("Import réussi !");
                        location.reload();
                    } else {
                        alert("Échec de l'import.");
                    }
                }
            };
            reader.readAsText(file);
        });

        // --- Back to Top & Scroll ---
        const bttBtn = document.getElementById("back-to-top-btn");
        window.addEventListener("scroll", () => {
            if (window.scrollY > 300) bttBtn.classList.add("visible");
            else bttBtn.classList.remove("visible");
        });
        bttBtn.addEventListener("click", () => {
            window.scrollTo({ top: 0, behavior: "smooth" });
        });

        // --- Print Helpers ---
        window.addEventListener("beforeprint", () => {
            document.querySelector(".dashboard-header").setAttribute("data-date", new Date().toLocaleDateString());
            // Ensure discrete mode is off for printing
            if (this.isDiscrete) document.body.classList.remove("discrete-mode");
        });
        window.addEventListener("afterprint", () => {
            if (this.isDiscrete) document.body.classList.add("discrete-mode");
        });

        // --- FILTERS & GENERATOR & MODAL (Same as v2 but hooked up) ---
        this.initDashboardLogic();
    }

    initDashboardLogic() {
        // Filters
        this.currentFilter = "all";
        document.querySelectorAll(".filter-chip").forEach(btn => {
            btn.addEventListener("click", (e) => {
                document.querySelectorAll(".filter-chip").forEach(b => b.classList.remove("active"));
                e.target.classList.add("active");
                this.currentFilter = e.target.dataset.category;
                this.renderEntries();
            });
        });

        // Generator
        const genInput = document.getElementById("generated-password");
        const lengthRange = document.getElementById("length-range");
        const lengthVal = document.getElementById("length-val");
        const updateGen = () => {
            const len = parseInt(lengthRange.value);
            lengthVal.textContent = len;
            const opts = {
                uppercase: document.getElementById("use-uppercase").checked,
                numbers: document.getElementById("use-numbers").checked,
                symbols: document.getElementById("use-symbols").checked
            };
            if (!opts.uppercase && !opts.numbers && !opts.symbols) { opts.uppercase = true; document.getElementById("use-uppercase").checked = true; }
            genInput.value = PasswordGenerator.generate(len, opts);
        };
        lengthRange.addEventListener("input", updateGen);
        document.getElementById("use-uppercase").addEventListener("change", updateGen);
        document.getElementById("use-numbers").addEventListener("change", updateGen);
        document.getElementById("use-symbols").addEventListener("change", updateGen);
        document.getElementById("refresh-generated-btn").addEventListener("click", updateGen);
        document.getElementById("copy-generated-btn").addEventListener("click", () => {
            navigator.clipboard.writeText(genInput.value);
            this.showNotification("Copié");
        });
        setTimeout(updateGen, 100);
        document.getElementById("save-generated-btn").addEventListener("click", () => {
            document.getElementById("entry-password").value = genInput.value;
            this.openModal();
        });

        // Modal
        document.getElementById("add-entry-btn").addEventListener("click", () => this.openModal());
        document.getElementById("close-modal").addEventListener("click", () => this.closeModal());
        document.getElementById("entry-form").addEventListener("submit", (e) => this.handleSaveEntry(e));
        document.getElementById("delete-entry-btn").addEventListener("click", () => this.handleDeleteEntry());
        document.getElementById("toggle-entry-pw-visibility").addEventListener("click", (e) => {
            const i = document.getElementById("entry-password");
            i.type = i.type === "password" ? "text" : "password";
        });
        document.getElementById("search-input").addEventListener("input", (e) => this.renderEntries(e.target.value));
    }

    /* --- LOGIC FLOWS --- */

    async handleUnlock() {
        const password = this.masterPasswordInput.value;
        if (!password) { return this.showNotification("Mot de passe requis", "error"); }

        const btn = document.getElementById("unlock-btn");
        btn.textContent = "Chargement...";
        btn.disabled = true;

        try {
            if (storageManager.exists()) {
                // --- UNLOCK (Login) ---
                const stored = storageManager.load();

                // 1. Get Salt match
                const salt = new Uint8Array(cryptoManager.base64ToBuffer(stored.salt));

                // 2. Derive User Wrapping Key
                const userKey = await cryptoManager.deriveWrappingKey(password, salt);

                // 3. Unwrap Vault Key
                try {
                    const wrappedUK = stored.wrappedUserKey;
                    this.vaultKey = await cryptoManager.unwrapKey(
                        cryptoManager.base64ToBuffer(wrappedUK.data),
                        userKey,
                        new Uint8Array(cryptoManager.base64ToBuffer(wrappedUK.iv))
                    );
                } catch (e) {
                    throw new Error("Mot de passe incorrect");
                }

                // 4. Decrypt Data
                this.entries = await cryptoManager.decryptData(
                    cryptoManager.base64ToBuffer(stored.vaultData.data),
                    new Uint8Array(cryptoManager.base64ToBuffer(stored.vaultData.iv)),
                    this.vaultKey
                );

                this.transitionToDashboard();

            } else {
                // --- CREATE (Setup) ---
                // 1. Generate keys
                this.vaultKey = await cryptoManager.generateVaultKey();
                const salt = cryptoManager.generateSalt();
                this.currentRecoveryCode = cryptoManager.generateRecoveryCode();

                const userKey = await cryptoManager.deriveWrappingKey(password, salt);
                const recoveryKey = await cryptoManager.deriveWrappingKey(this.currentRecoveryCode, salt);

                // 2. Wrap Vault Key with both
                const wrappedUserKey = await cryptoManager.wrapKey(this.vaultKey, userKey);
                const wrappedRecoveryKey = await cryptoManager.wrapKey(this.vaultKey, recoveryKey);

                // 3. Encrypt empty data
                this.entries = [];
                const encData = await cryptoManager.encryptData(this.entries, this.vaultKey);

                // 4. Save Everything
                const payload = {
                    salt: cryptoManager.uint8ToBase64(salt),
                    wrappedUserKey: {
                        iv: cryptoManager.uint8ToBase64(wrappedUserKey.iv),
                        data: cryptoManager.bufferToBase64(wrappedUserKey.ciphertext)
                    },
                    wrappedRecoveryKey: {
                        iv: cryptoManager.uint8ToBase64(wrappedRecoveryKey.iv),
                        data: cryptoManager.bufferToBase64(wrappedRecoveryKey.ciphertext)
                    },
                    vaultData: {
                        iv: cryptoManager.uint8ToBase64(encData.iv),
                        data: cryptoManager.bufferToBase64(encData.ciphertext)
                    }
                };

                storageManager.save(payload);

                // 5. Show Recovery Code
                this.authSection.classList.add("hidden");
                this.recoveryInitSection.classList.remove("hidden");
                document.getElementById("new-recovery-code").textContent = this.currentRecoveryCode;
            }
        } catch (error) {
            console.error(error);
            this.showNotification(error.message, "error");
            btn.textContent = "Déverrouiller / Créer";
            btn.disabled = false;
        }
    }

    async saveVault() {
        if (!this.vaultKey) return;

        // Encrypt Data
        const encData = await cryptoManager.encryptData(this.entries, this.vaultKey);

        // We need to preserve the existing keys (wrappedUserKey, wrappedRecoveryKey)
        // because we don't have the user's password or recovery code in memory to re-wrap them.
        const existing = storageManager.load();

        const payload = {
            version: 3,
            salt: existing.salt,
            wrappedUserKey: existing.wrappedUserKey,
            wrappedRecoveryKey: existing.wrappedRecoveryKey,
            vaultData: {
                iv: cryptoManager.uint8ToBase64(encData.iv),
                data: cryptoManager.bufferToBase64(encData.ciphertext)
            }
        };
        storageManager.save(payload);
    }

    /* --- RECOVERY LOGIC --- */

    showRecoveryFlow() {
        this.authSection.classList.add("hidden");
        this.recoveryFlowSection.classList.remove("hidden");
        document.getElementById("step-recover-1").classList.remove("hidden");
        document.getElementById("step-recover-2").classList.add("hidden");
    }

    async handleRecoveryVerify() {
        const code = document.getElementById("recovery-code-input").value.trim().toUpperCase();
        if (!code) return this.showNotification("Code requis", "error");

        try {
            const stored = storageManager.load();
            const salt = new Uint8Array(cryptoManager.base64ToBuffer(stored.salt));
            const recoveryKey = await cryptoManager.deriveWrappingKey(code, salt);

            // Try to unwrap Vault Key with Recovery Key
            try {
                const wrappedRK = stored.wrappedRecoveryKey;
                this.vaultKey = await cryptoManager.unwrapKey(
                    cryptoManager.base64ToBuffer(wrappedRK.data),
                    recoveryKey,
                    new Uint8Array(cryptoManager.base64ToBuffer(wrappedRK.iv))
                );

                // If successful, we have the Vault Key!
                // Unlock step 2
                document.getElementById("step-recover-1").classList.add("hidden");
                document.getElementById("step-recover-2").classList.remove("hidden");
                this.showNotification("Code validé !", "success");

            } catch (e) {
                throw new Error("Code de secours invalide");
            }
        } catch (e) {
            this.showNotification(e.message, "error");
        }
    }

    async handleRecoveryReset() {
        const newPassword = document.getElementById("new-master-password").value;
        if (!newPassword) return this.showNotification("Mot de passe requis", "error");

        try {
            // We have this.vaultKey from the previous step.
            // We need to re-wrap it with the new password.
            const stored = storageManager.load();
            const salt = new Uint8Array(cryptoManager.base64ToBuffer(stored.salt));

            const newUserKey = await cryptoManager.deriveWrappingKey(newPassword, salt);
            const newWrappedUserKey = await cryptoManager.wrapKey(this.vaultKey, newUserKey);

            // Update Storage: Keep recovery key same, Keep salt same, Update User Key
            const payload = {
                version: 3,
                salt: stored.salt,
                wrappedUserKey: {
                    iv: cryptoManager.uint8ToBase64(newWrappedUserKey.iv),
                    data: cryptoManager.bufferToBase64(newWrappedUserKey.ciphertext)
                },
                wrappedRecoveryKey: stored.wrappedRecoveryKey, // Unchanged
                vaultData: stored.vaultData // Unchanged
            };

            storageManager.save(payload);

            alert("Mot de passe réinitialisé avec succès !");
            location.reload();

        } catch (e) {
            console.error(e);
            this.showNotification("Erreur lors de la réinitialisation", "error");
        }
    }

    /* --- TRANSITIONS & HELPERS --- */

    /* --- AUTOLOCK & HELPERS --- */

    initAutoLock() {
        const resetTimer = () => {
            if (this.inactivityTimer) clearTimeout(this.inactivityTimer);
            if (!this.vaultKey) return; // Only if unlocked

            this.inactivityTimer = setTimeout(() => {
                alert("Verrouillage automatique pour inactivité.");
                location.reload();
            }, 5 * 60 * 1000); // 5 minutes
        };

        window.addEventListener("mousemove", resetTimer);
        window.addEventListener("keypress", resetTimer);
        window.addEventListener("click", resetTimer);
        window.addEventListener("scroll", resetTimer);
    }

    transitionToDashboard() {
        this.recoveryInitSection.classList.add("hidden");
        this.recoveryFlowSection.classList.add("hidden");
        this.authSection.classList.add("hidden");
        this.dashboardSection.classList.remove("hidden");
        this.renderEntries();
        this.initAutoLock(); // Start Timer
    }

    renderEntries(filter = "") {
        // ... (Same rendering logic as v2) ...
        this.entriesList.innerHTML = "";
        let filtered = this.entries; // this.entries is set during unlock

        if (this.currentFilter !== "all") {
            filtered = filtered.filter(e => e.category === this.currentFilter);
        }
        if (filter) {
            const q = filter.toLowerCase();
            filtered = filtered.filter(e => e.title.toLowerCase().includes(q) || (e.username && e.username.toLowerCase().includes(q)));
        }

        if (filtered.length === 0) {
            this.entriesList.innerHTML = '<p style="text-align:center;color:var(--text-muted);padding:20px;">Aucun.</p>';
            return;
        }

        filtered.forEach(entry => {
            const div = document.createElement("div");
            div.className = "entry-item";
            const strength = SecurityAnalyzer.analyze(entry.password);
            const isReused = SecurityAnalyzer.checkReuse(entry.password, this.entries, entry.id);
            const badgeClass = `security-${strength}`;
            div.innerHTML = `
                <div class="entry-icon"><i class="fa-solid fa-key"></i></div>
                <div class="entry-details">
                    <span class="entry-title">${this.escapeHtml(entry.title)}</span>
                    <span class="entry-username">
                        ${this.escapeHtml(entry.username || "---")} 
                        <span style="font-size:0.7em; opacity:0.6;">(${entry.category || "Autre"})</span>
                        ${entry.url ? `<a href="${this.escapeHtml(entry.url)}" target="_blank" class="entry-link-btn" title="Ouvrir le site" onclick="event.stopPropagation()"><i class="fa-solid fa-arrow-up-right-from-square"></i></a>` : ''}
                        ${entry.notes ? `<i class="fa-regular fa-sticky-note" title="Notes disponibles" style="margin-left:8px; font-size:0.8em; opacity:0.7"></i>` : ''}
                    </span>
                    ${isReused ? '<span class="reused-warning"><i class="fa-solid fa-triangle-exclamation"></i> Réutilisé</span>' : ''}
                </div>
                <div class="security-badge ${badgeClass}"></div>
            `;
            div.addEventListener("click", () => this.openModal(entry));
            this.entriesList.appendChild(div);
        });
    }

    // Modal Helpers
    openModal(entry = null) {
        this.modal.classList.remove("hidden");
        const deleteBtn = document.getElementById("delete-entry-btn");
        if (entry) {
            document.getElementById("modal-title").textContent = "Modifier";
            document.getElementById("entry-id").value = entry.id;
            document.getElementById("entry-title").value = entry.title;
            document.getElementById("entry-username").value = entry.username;
            document.getElementById("entry-password").value = entry.password;
            document.getElementById("entry-category").value = entry.category || "Autre";
            document.getElementById("entry-url").value = entry.url || "";
            document.getElementById("entry-notes").value = entry.notes || "";
            deleteBtn.classList.remove("hidden");
        } else {
            document.getElementById("modal-title").textContent = "Ajouter";
            document.getElementById("entry-id").value = "";
            document.getElementById("entry-title").value = "";
            document.getElementById("entry-username").value = "";
            document.getElementById("entry-category").value = "Autre";
            document.getElementById("entry-url").value = "";
            document.getElementById("entry-notes").value = "";
            deleteBtn.classList.add("hidden");
        }
    }
    closeModal() { this.modal.classList.add("hidden"); document.getElementById("entry-password").value = ""; }

    async handleSaveEntry(e) {
        e.preventDefault();
        const id = document.getElementById("entry-id").value;
        const title = document.getElementById("entry-title").value;
        const username = document.getElementById("entry-username").value;
        const password = document.getElementById("entry-password").value;
        const category = document.getElementById("entry-category").value;
        const url = document.getElementById("entry-url").value;
        const notes = document.getElementById("entry-notes").value;

        if (id) {
            const index = this.entries.findIndex(x => x.id === id);
            if (index !== -1) this.entries[index] = { ...this.entries[index], title, username, password, category, url, notes, updatedAt: Date.now() };
        } else {
            this.entries.push({ id: crypto.randomUUID(), title, username, password, category, url, notes, createdAt: Date.now() });
        }
        await this.saveVault();
        this.renderEntries();
        this.closeModal();
        this.showNotification("Sauvegardé");
    }

    async handleDeleteEntry() {
        const id = document.getElementById("entry-id").value;
        if (confirm("Supprimer ?")) {
            this.entries = this.entries.filter(e => e.id !== id);
            await this.saveVault();
            this.renderEntries();
            this.closeModal();
        }
    }

    showNotification(msg, type = "success") {
        const div = document.createElement("div"); div.className = "notification"; div.textContent = msg;
        if (type === "error") div.style.borderLeftColor = "#ff3b30";
        this.notificationArea.appendChild(div);
        setTimeout(() => { div.style.opacity = "0"; setTimeout(() => div.remove(), 300); }, 3000);
    }
    escapeHtml(t) { if (!t) return ""; return t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
}

const cryptoManager = new CryptoManager();
const storageManager = new StorageManager();
document.addEventListener("DOMContentLoaded", () => new UIManager());
