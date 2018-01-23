package com.parkerneff.jwt;

import org.junit.Test;

import java.security.KeyPair;
import java.util.Map;
import static org.junit.Assert.*;

public class TestKeyPairService {
    @Test
    public void testKeyMap() {
        KeyPairService keyPairService = new KeyPairService();
        Map<String, KeyPair> keyMap = keyPairService.getKeyPairs();
        assertEquals(1, keyMap.size());

    }
}
