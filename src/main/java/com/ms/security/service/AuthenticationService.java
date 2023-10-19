package com.ms.security.service;


import com.ms.security.dao.request.SignUpRequest;
import com.ms.security.dao.response.JwtAuthenticationResponse;

public interface AuthenticationService {
    JwtAuthenticationResponse signup(SignUpRequest request);

    JwtAuthenticationResponse signin(SignUpRequest request);
}
