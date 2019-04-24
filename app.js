const API_ENDPOINT = (hash) => `https://api.pwnedpasswords.com/range/${hash.substring(0,5)}`;

class AppController {

    async submit() {
        let password    = document.forms.pwned.password.value;
        let sha1Hash    = await this.hashPassword(password);
        let results     = await this.getPwnedPasswordHashes(sha1Hash);
        let hashes      = this.toJSON(results);
        let isPwned     = this.hasMatch(sha1Hash, hashes);

        this.renderResults(sha1Hash, isPwned, hashes);
    }

    async getPwnedPasswordHashes(sha1Hash) {
        let url = API_ENDPOINT(sha1Hash);

        return fetch(url).then((response) => response.text());
    }

    async hashPassword(password) {

        const encoder   = new TextEncoder();
        const data      = encoder.encode(password);

        return window.crypto.subtle.digest('SHA-1', data).then((digest) => this.hexString(digest));
    }

    hasMatch(hash, hashes) {
        return hashes.find((item) => item.hash.localeCompare(hash));
    }

    renderResults(sha1Hash, isPwned, results) {

        document.getElementById('hash').innerText           = sha1Hash;
        document.getElementById('matches').innerText        = results.length;
        document.getElementById('exact-match').innerText    = isPwned ? 'Yes' : 'No';
    }

    toJSON(data) {
        return data.split('\n').map((line) => {
            let [hash, occurances] = line.split(':');
            return {hash, occurances};
        });
    }

    hexString(buffer) {
        const byteArray = new Uint8Array(buffer);
      
        const hexCodes = [...byteArray].map(value => {
            const hexCode = value.toString(16);
            const paddedHexCode = hexCode.padStart(2, '0');
            return paddedHexCode;
        });
      
        return hexCodes.join('');
    }
}

var app = new AppController();
