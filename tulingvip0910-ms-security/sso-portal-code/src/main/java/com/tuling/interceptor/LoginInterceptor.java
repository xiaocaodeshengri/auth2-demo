package com.tuling.interceptor;

import com.alibaba.fastjson.JSON;
import com.tuling.config.MDA;
import com.tuling.entity.TokenInfo;
import com.tuling.vo.Result;
import com.tuling.vo.SystemErrorType;
import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.jni.Local;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.time.LocalDateTime;

/**
 * 过滤session中是否有token信息(基于Session的单点登陆)
 * Created by smlz on 2019/12/29.
 */
@Slf4j
@Component
public class LoginInterceptor implements HandlerInterceptor {

    @Autowired
    private RestTemplate restTemplate;

    public static final String loginUrl = "http://auth.tuling.com:8888/oauth/authorize?response_type=code&client_id=portal_app&redirect_uri=http://portal.tuling.com:8855/callBack&state=";

    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        //从session中获取出token的信息
        HttpSession session = request.getSession();

        TokenInfo tokenInfo = (TokenInfo) session.getAttribute(MDA.TOKEN_INFO_KEY);

        if(tokenInfo == null) {

            String url = request.getRequestURL().toString();

            log.info("需要登陆的url:{}",url);
            //重定向到登陆页面
            response.sendRedirect(loginUrl+url);
            return false;
        }else {
            log.info("portal-web中的session中的tokenInfo的有效期:{},当前时间:{}",tokenInfo.getExpireTime(), LocalDateTime.now());
            //判断accessToken是否过期，若过期的话 就需要通过刷新令牌去刷新我们的accessToken
            if(tokenInfo.isExpire()) {
                log.info("accessToken失效:{},accessToken有效期:{},当前时间:{}",tokenInfo.getAccess_token(),tokenInfo.getExpireTime(), LocalDateTime.now());
                //通过refreshToken刷新我们的accessToken
                HttpHeaders httpHeaders = new HttpHeaders();
                httpHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
                httpHeaders.setBasicAuth(MDA.CLIENT_ID,MDA.CLIENT_SECRET);

                MultiValueMap<String,String> param = new LinkedMultiValueMap<>();
                param.add("grant_type","refresh_token");
                param.add("refresh_token",tokenInfo.getRefresh_token());

                HttpEntity<MultiValueMap<String,String>> httpEntity = new HttpEntity<>(param,httpHeaders);


                ResponseEntity<TokenInfo> responseEntity =null;
                try {
                    responseEntity = restTemplate.exchange(MDA.AUTH_SERVER_URL, HttpMethod.POST, httpEntity, TokenInfo.class);
                    TokenInfo newTokenInfo = responseEntity.getBody().initExpireTime();

                    request.getSession().setAttribute(MDA.TOKEN_INFO_KEY,newTokenInfo);
                }catch (Exception e) {

                    //refresh_token失效了 从新走认证服务器流程
                    log.warn("根据refresh_token:{}获取access_token失败",tokenInfo.getRefresh_token());
                    String contentType = request.getContentType();
                    //表示的ajax请求
                    if(contentType!=null && contentType.contains(MediaType.APPLICATION_JSON_UTF8.toString())) {
                        response.setContentType(MediaType.APPLICATION_JSON_UTF8.toString());
                        response.getWriter().write(JSON.toJSONString(Result.fail(SystemErrorType.REFRESH_TOKEN_EXPIRE)));
                        return false;
                    }

                    //通过刷新token获取 accessToken失败,从新登陆
                    String url = "http://portal.tuling.com:8855/home.html";
                    //重定向到登陆页面
                    log.info("重定向URL:{}",(loginUrl+url));
                    response.sendRedirect(loginUrl+url);
                    return false;
                }

            }
        }

        return true;
    }
}
