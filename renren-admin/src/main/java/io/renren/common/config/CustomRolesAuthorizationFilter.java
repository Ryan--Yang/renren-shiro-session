package io.renren.common.config;

import io.renren.common.utils.RedisKeys;
import io.renren.common.utils.SpringContextUtils;
import io.renren.modules.sys.entity.SysUserEntity;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authz.AuthorizationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * @author ryan--yang
 * @email yangrui@cetcbigdata.com
 * @date 2018-9-4 15:23
 */

@Component
public class CustomRolesAuthorizationFilter extends AuthorizationFilter {

    @Override
    protected boolean isAccessAllowed(ServletRequest servletRequest, ServletResponse servletResponse, Object o) throws Exception {
        Subject subject = getSubject(servletRequest,servletResponse);
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        String localAddr = request.getRequestURI();
        PrincipalCollection principals = subject.getPrincipals();
        SysUserEntity user = (SysUserEntity)principals.getPrimaryPrincipal();
        Long userId = user.getUserId();

        /*List<String> permsList = (List<String>)*/
        RedisTemplate redisTemplate = (RedisTemplate)SpringContextUtils.getBean("redisTemplate");
                redisTemplate.opsForValue().get(RedisKeys.getAuthoritySessionKey(userId));

        Session session = subject.getSession();
        return true;
    }
}
