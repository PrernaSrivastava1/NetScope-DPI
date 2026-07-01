package com.packetanalyzer.rules;

import com.packetanalyzer.model.AppType;
import org.junit.jupiter.api.Test;
import java.io.File;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.*;

public class RuleManagerTest {

    @Test
    public void testBlockingRules() {
        RuleManager rm = new RuleManager();

        // 1. IP Blocking
        String testIpStr = "192.168.1.50";
        int testIp = RuleManager.parseIP(testIpStr);
        rm.blockIP(testIp);
        assertTrue(rm.isIPBlocked(testIp));
        assertFalse(rm.isIPBlocked(RuleManager.parseIP("192.168.1.100")));

        // 2. Port Blocking
        rm.blockPort(8080);
        assertTrue(rm.isPortBlocked(8080));
        assertFalse(rm.isPortBlocked(80));

        // 3. App Blocking
        rm.blockApp(AppType.YOUTUBE);
        assertTrue(rm.isAppBlocked(AppType.YOUTUBE));
        assertFalse(rm.isAppBlocked(AppType.FACEBOOK));

        // 4. Domain Blocking
        rm.blockDomain("tiktok.com");
        assertTrue(rm.isDomainBlocked("tiktok.com"));
        assertFalse(rm.isDomainBlocked("google.com"));

        // Wildcard Domain
        rm.blockDomain("*.facebook.com");
        assertTrue(rm.isDomainBlocked("facebook.com"));
        assertTrue(rm.isDomainBlocked("www.facebook.com"));
        assertTrue(rm.isDomainBlocked("api.facebook.com"));
        assertFalse(rm.isDomainBlocked("myfacebook.com"));

        // 5. Combined ShouldBlock check
        Optional<BlockReason> reason = rm.shouldBlock(testIp, 443, AppType.UNKNOWN, "google.com");
        assertTrue(reason.isPresent());
        assertEquals(BlockReason.Type.IP, reason.get().getType());
        assertEquals(testIpStr, reason.get().getDetail());

        reason = rm.shouldBlock(RuleManager.parseIP("192.168.1.1"), 8080, AppType.UNKNOWN, "google.com");
        assertTrue(reason.isPresent());
        assertEquals(BlockReason.Type.PORT, reason.get().getType());
        assertEquals("8080", reason.get().getDetail());

        reason = rm.shouldBlock(RuleManager.parseIP("192.168.1.1"), 443, AppType.YOUTUBE, "google.com");
        assertTrue(reason.isPresent());
        assertEquals(BlockReason.Type.APP, reason.get().getType());
        assertEquals("YouTube", reason.get().getDetail());

        reason = rm.shouldBlock(RuleManager.parseIP("192.168.1.1"), 443, AppType.UNKNOWN, "api.facebook.com");
        assertTrue(reason.isPresent());
        assertEquals(BlockReason.Type.DOMAIN, reason.get().getType());
        assertEquals("api.facebook.com", reason.get().getDetail());

        reason = rm.shouldBlock(RuleManager.parseIP("192.168.1.1"), 443, AppType.UNKNOWN, "google.com");
        assertFalse(reason.isPresent());
    }

    @Test
    public void testRulesPersistence() {
        RuleManager rm1 = new RuleManager();
        rm1.blockIP("192.168.1.50");
        rm1.blockApp(AppType.YOUTUBE);
        rm1.blockDomain("*.tiktok.com");
        rm1.blockPort(8080);

        String tempRulesPath = "temp_rules.txt";
        File file = new File(tempRulesPath);
        if (file.exists()) {
            file.delete();
        }

        assertTrue(rm1.saveRules(tempRulesPath));
        assertTrue(file.exists());

        RuleManager rm2 = new RuleManager();
        assertTrue(rm2.loadRules(tempRulesPath));

        RuleManager.RuleStats stats = rm2.getStats();
        assertEquals(1, stats.blockedIps);
        assertEquals(1, stats.blockedApps);
        assertEquals(1, stats.blockedDomains);
        assertEquals(1, stats.blockedPorts);

        assertTrue(rm2.isIPBlocked(RuleManager.parseIP("192.168.1.50")));
        assertTrue(rm2.isAppBlocked(AppType.YOUTUBE));
        assertTrue(rm2.isDomainBlocked("www.tiktok.com"));
        assertTrue(rm2.isPortBlocked(8080));

        // Clean up
        file.delete();
    }
}
