package biz.neustar.idaasrest.api;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import biz.neustar.idaasrest.api.jwt.IJwtTokenUtil;

import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import biz.neustar.idaas.common.model.ServiceLocator;
import lombok.extern.log4j.Log4j2;

@Component
@Log4j2
public class CORSFilter implements Filter {


	private IJwtTokenUtil jwt = null;
    /**
     * Set CORS filter
     * @param req
     * @param res
     * @param chain
     * @throws IOException
     * @throws ServletException
     */
	@Override
	public void doFilter(ServletRequest req, ServletResponse res,
			FilterChain chain) throws IOException, ServletException {

		final HttpServletRequest request = (HttpServletRequest) req;
		final HttpServletResponse response = (HttpServletResponse) res;

		if (log.isTraceEnabled())
			log.trace("****CORSFilter called,method is: **** {}, url: {}",request.getMethod(),request.getRequestURL());

        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "POST, GET, PUT, OPTIONS, DELETE, PATCH");
        response.setHeader("Access-Control-Max-Age", "3600");
        response.setHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, X-Authorization, Authorization, authorization");
        response.setHeader("Access-Control-Expose-Headers", "Location");
        response.setHeader("Content-Type", "application/octet-stream");

        try {
			if ("OPTIONS".equals(request.getMethod())) {
				chain.doFilter(req, res);
				response.setStatus(HttpServletResponse.SC_OK);
			} else {
				Assert.isTrue(request instanceof HttpServletRequest, "This is Http Request");
				HttpServletRequest httpServletRequest = HttpServletRequest.class.cast(request);
				String uri = httpServletRequest.getRequestURI();
				String query = httpServletRequest.getQueryString();
				if (query != null) {
					uri = uri + "?" + query;
				}
				log.trace("New request for {}", uri);
				long startTime = System.currentTimeMillis();
				chain.doFilter(request, response);
				long timeTaken = System.currentTimeMillis() - startTime;
				if (jwt == null)
					jwt = ServiceLocator.getInstance().getApplicationContext().getBean(IJwtTokenUtil.class);
				Long userId = jwt != null ? jwt.getUserId(request) : -1L;
				if (! (userId == -1L || uri.startsWith("/api/ems")) )
					log.debug("Request from remoteip: {} by user: {}, url: {} took {} ms.", httpServletRequest.getRemoteAddr(), userId, uri, timeTaken);
			}
        } catch (Throwable t) {
        	response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        }
	}
}
