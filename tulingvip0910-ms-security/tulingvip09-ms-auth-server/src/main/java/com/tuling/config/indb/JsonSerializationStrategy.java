package com.tuling.config.indb;

import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.security.oauth2.provider.token.store.redis.StandardStringSerializationStrategy;
import org.springframework.stereotype.Component;

/**
 * json序列化器
 * Created by smlz on 2020/3/6.
 */
@Component
public class JsonSerializationStrategy extends StandardStringSerializationStrategy {

    private Jackson2JsonRedisSerializer jackson2JsonRedisSerializer= new Jackson2JsonRedisSerializer(Object.class);
    @Override
    protected <T> T deserializeInternal(byte[] bytes, Class<T> clazz) {
        return (T) jackson2JsonRedisSerializer.deserialize(bytes);
    }

    @Override
    protected byte[] serializeInternal(Object object) {
        return jackson2JsonRedisSerializer.serialize(object);
    }
}
