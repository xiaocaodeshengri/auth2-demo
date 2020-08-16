package com.tuling.interceptor;

import com.alibaba.fastjson.JSON;
import com.tuling.config.MDA;
import com.tuling.entity.TokenInfo;
import com.tuling.util.CookieUtils;
import com.tuling.vo.Result;
import com.tuling.vo.SystemErrorType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
* @vlog: 高于生活，源于生活
* @desc: 类的描述:基于Cookie的单点登陆模式
* @author: smlz
* @createDate: 2020/1/20 20:50
* @version: 1.0
*/
/*@Component*/
@Slf4j
public class CookieLoginInterceptor implements HandlerInterceptor {

    public static final String loginUrl = "http://auth.tuling.com:8888/oauth/authorize?response_type=code&client_id=portal_app&redirect_uri=http://portal.tuling.com:8855/callBack&state=";

    @Autowired
    private RestTemplate restTemplate;

    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {

        //先从cookie中读取accessToken的值
        String accessTokenInCookie = CookieUtils.readCookieValue(request, MDA.COOKIE_ACCESS_TOKEN_KEY);
        log.info("从cookie中读取AccessToken的值:{}",accessTokenInCookie);

        //从cookie中获取refreshToken的值
        String refreshTokenInCookie = CookieUtils.readCookieValue(request, MDA.COOKIE_REFRESH_TOKEN_KEY);
        log.info("从cookie中读取ReFreshToken的值:{}",refreshTokenInCookie);


        //若cookie中的accessToken没有过期,我们拦截器就直接放行,不进行拦截
        if(!StringUtils.isEmpty(accessTokenInCookie)) {
            response.setHeader(MDA.COOKIE_ACCESS_TOKEN_KEY,accessTokenInCookie);
            return true;
        }else {
            //accessToken已经失效了,但是我们的cookie中的refreshToken没有过期,我们需要通过刷新令牌去进行刷新
            //我们的accessToken
            if(!StringUtils.isEmpty(refreshTokenInCookie)) {
                //刷新令牌不为空
                HttpHeaders httpHeaders = new HttpHeaders();
                httpHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
                httpHeaders.setBasicAuth(MDA.CLIENT_ID,MDA.CLIENT_SECRET);

                MultiValueMap<String,String> param = new LinkedMultiValueMap<>();
                param.add("grant_type","refresh_token");
                param.add("refresh_token",refreshTokenInCookie);

                HttpEntity<MultiValueMap<String,String>> httpEntity = new HttpEntity<>(param,httpHeaders);


                ResponseEntity<TokenInfo> responseEntity =null;
                try {

                    //刷新我们的令牌
                    responseEntity = restTemplate.exchange(MDA.AUTH_SERVER_URL, HttpMethod.POST, httpEntity, TokenInfo.class);
                    TokenInfo newTokenInfo = responseEntity.getBody().initExpireTime();

                    //把新的令牌存储到我们的cookie中
                    CookieUtils.writeCookie(response,newTokenInfo);
                    response.setHeader(MDA.COOKIE_ACCESS_TOKEN_KEY,newTokenInfo.getAccess_token());
                }catch (Exception e) {

                    //认证服务器上的refreshToken 刷新失败了(一般是我们的刷新令牌过期了)
                    log.warn("认证服务器上的refreshToken已经过期",refreshTokenInCookie);
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

            }else {
                //客户端的cookie中的refreshToken已经失效了
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
        return true;
    }

}
