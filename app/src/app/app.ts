import {Component, OnInit} from '@angular/core';
import { RouterOutlet } from '@angular/router';
import {JsonPipe, NgIf} from '@angular/common';
import {OAuthService} from 'angular-oauth2-oidc';
import {authConfig} from './auth.config';

  @Component({
    standalone:true,
    selector: 'app-root',
    imports: [RouterOutlet, NgIf, JsonPipe],
    templateUrl: './app.html',
    styleUrl: './app.css'
  })
  export class App implements OnInit {
  protected title = 'app';
  constructor(public oauthService: OAuthService) {
    this.configureAuth();
  }

    ngOnInit(): void {

    console.log('ngOnInit appjs');
      }

  configureAuth() {
    this.oauthService.configure(authConfig);
    this.oauthService.loadDiscoveryDocumentAndTryLogin();
  }

  login() {
    this.oauthService.initCodeFlow();
  }

  logout() {
    this.oauthService.logOut();
  }

  getIdToken() {
    return this.oauthService.getIdentityClaims();
  }
}
