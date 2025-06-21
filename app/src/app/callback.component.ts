import { Component, inject, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router } from '@angular/router';
import { OAuthService } from 'angular-oauth2-oidc';

@Component({
  selector: 'app-callback',
  standalone: true,
  imports: [CommonModule],
  template: `<p>Signing you in...</p>`,
})
export class CallbackComponent implements OnInit {
  constructor(private readonly oauthService: OAuthService) {}


  ngOnInit() {
    console.log('ngOnInit callback');

    this.oauthService.tryLoginCodeFlow().then(() => {
      if (this.oauthService.hasValidAccessToken()) {
        console.log('✅ Access token:', this.oauthService.getAccessToken());
      } else {
        console.error('❌ Login failed or access token invalid');
      }
    });
  }
}
