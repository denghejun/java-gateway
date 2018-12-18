package com.github.hejun.filters;

import com.google.common.net.HttpHeaders;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class AccessFilter extends ZuulFilter {

    @Value("${application.regex.static-resources}")
    private String staticResourceReg;

    @Value("${application.ignored-url}")
    private String ignoredUrls;

    @Override
    public String filterType() {
        return "pre";
    }

    @Override
    public int filterOrder() {
        return 0;
    }

    public boolean shouldFilter() {
        String requestUri = RequestContext.getCurrentContext().getRequest().getRequestURI();
        if (requestUri == null) {
            return false;
        } else {
            Pattern pattern = Pattern.compile(staticResourceReg, Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(requestUri);
            return !matcher.find();
        }
    }

    public Object run() {
        RequestContext ctx = RequestContext.getCurrentContext();
        HttpServletRequest request = ctx.getRequest();
        String token = request.getHeader(HttpHeaders.AUTHORIZATION);
        String requestUri = request.getRequestURI();
        String[] ignores = ignoredUrls.split(",");
        for (String ignore : ignores) {
            if (requestUri.indexOf(ignore) >= 0) {
                return null;
            }
        }

        if (token == null || token.equals("")) {
            ctx.setSendZuulResponse(false);
            ctx.setResponseStatusCode(401);

            return null;

        }

        return null;
    }
}
