//package com.ms.security.filter;
//
//import jakarta.servlet.*;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.extern.log4j.Log4j2;
//import org.springframework.stereotype.Component;
//import org.springframework.util.Assert;
//
//import java.io.IOException;
//
//@Component
//@Log4j2
//public class CORSFilter implements Filter {
//
//
//    /**
//     * Set CORS filter
//     * @param req
//     * @param res
//     * @param chain
//     * @throws IOException
//     * @throws ServletException
//     */
//	@Override
//	public void doFilter(ServletRequest req, ServletResponse res,
//						 FilterChain chain) throws IOException, ServletException {
//
//		final HttpServletRequest request = (HttpServletRequest) req;
//		final HttpServletResponse response = (HttpServletResponse) res;
//
//		if (log.isTraceEnabled())
//			log.trace("****CORSFilter called,method is: **** {}, url: {}",request.getMethod(),request.getRequestURL());
//
//        response.setHeader("Access-Control-Allow-Origin", "*");
//        response.setHeader("Access-Control-Allow-Methods", "POST, GET, PUT, OPTIONS, DELETE, PATCH");
//        response.setHeader("Access-Control-Max-Age", "3600");
//        response.setHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, X-Authorization, Authorization, authorization");
//        response.setHeader("Access-Control-Expose-Headers", "Location");
//        response.setHeader("Content-Type", "application/octet-stream");
//
//        try {
//			if ("OPTIONS".equals(request.getMethod())) {
//				chain.doFilter(req, res);
//				response.setStatus(HttpServletResponse.SC_OK);
//			} else {
//				Assert.isTrue(request instanceof HttpServletRequest, "This is Http Request");
//				HttpServletRequest httpServletRequest = HttpServletRequest.class.cast(request);
//				String uri = httpServletRequest.getRequestURI();
//				String query = httpServletRequest.getQueryString();
//				if (query != null) {
//					uri = uri + "?" + query;
//				}
//				log.trace("New request for {}", uri);
//				long startTime = System.currentTimeMillis();
//				chain.doFilter(request, response);
//			}
//        } catch (Throwable t) {
//        	response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
//        }
//	}
//}
