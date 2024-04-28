import { Component } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { RouterOutlet } from '@angular/router';
import { gcm as cgmCipher } from '@noble/ciphers/aes';
import { utf8ToBytes } from '@noble/ciphers/utils';
import { gcm as gcmWebcrypto, randomBytes } from '@noble/ciphers/webcrypto';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha256';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [
    RouterOutlet,
    ReactiveFormsModule
  ],
  templateUrl: './app.component.html',
  styleUrl: './app.component.scss'
})
export class AppComponent {

  cipherForm = this.fb.group({
    content: [ '', [ Validators.required ] ],
    password: [ '', [ Validators.required ] ]
  });

  webkitForm = this.fb.group({
    content: [ '', [ Validators.required ] ],
    password: [ '', [ Validators.required ] ]
  });

  constructor(
    private fb: FormBuilder
  ) { }

  onSubmitCipher(): void {
    if (this.cipherForm.valid) {
      const raw = this.cipherForm.getRawValue();

      const nonce = randomBytes(12);
      const content = utf8ToBytes(raw.content || '');
      const salt = randomBytes(8);

      const key = pbkdf2(sha256, raw.password || '', salt, {
        c: 10,
        dkLen: 32
      });

      const encrypted = cgmCipher(key, nonce).encrypt(content);
      console.info({
        cipher: encrypted,
        salt,
        nonce
      });
    }
  }

  onSubmitWebkit(): void {
    if (this.webkitForm.valid) {
      const raw = this.webkitForm.getRawValue();

      const nonce = randomBytes(12);
      const content = utf8ToBytes(raw.content || '');
      const salt = randomBytes(8);

      const key = pbkdf2(sha256, raw.password || '', salt, {
        c: 10,
        dkLen: 32
      });

      const encrypted = gcmWebcrypto(key, nonce)
        .encrypt(content)
        .then(encrypted => {
          console.info({
            cipher: encrypted,
            salt,
            nonce
          });
        })
        .catch(e => console.error(e));
    }
  }
}
