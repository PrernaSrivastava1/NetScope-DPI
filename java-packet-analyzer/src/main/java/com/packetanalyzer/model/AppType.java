package com.packetanalyzer.model;

public enum AppType {
    UNKNOWN("Unknown"),
    HTTP("HTTP"),
    HTTPS("HTTPS"),
    DNS("DNS"),
    TLS("TLS"),
    QUIC("QUIC"),
    GOOGLE("Google"),
    FACEBOOK("Facebook"),
    YOUTUBE("YouTube"),
    TWITTER("Twitter/X"),
    INSTAGRAM("Instagram"),
    NETFLIX("Netflix"),
    AMAZON("Amazon"),
    MICROSOFT("Microsoft"),
    APPLE("Apple"),
    WHATSAPP("WhatsApp"),
    TELEGRAM("Telegram"),
    TIKTOK("TikTok"),
    SPOTIFY("Spotify"),
    ZOOM("Zoom"),
    DISCORD("Discord"),
    GITHUB("GitHub"),
    CLOUDFLARE("Cloudflare");

    private final String displayName;

    AppType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }

    public static AppType fromString(String name) {
        for (AppType type : AppType.values()) {
            if (type.getDisplayName().equalsIgnoreCase(name)) {
                return type;
            }
        }
        return UNKNOWN;
    }

    public static AppType sniToAppType(String sni) {
        if (sni == null || sni.isEmpty()) {
            return UNKNOWN;
        }

        String lowerSni = sni.toLowerCase();

        // Check for known patterns in the exact order as C++:
        // 1. Google (which ownership includes YouTube, but check 'google' pattern first)
        if (lowerSni.contains("google") ||
            lowerSni.contains("gstatic") ||
            lowerSni.contains("googleapis") ||
            lowerSni.contains("ggpht") ||
            lowerSni.contains("gvt1")) {
            return GOOGLE;
        }

        // 2. YouTube
        if (lowerSni.contains("youtube") ||
            lowerSni.contains("ytimg") ||
            lowerSni.contains("youtu.be") ||
            lowerSni.contains("yt3.ggpht")) {
            return YOUTUBE;
        }

        // 3. Facebook/Meta
        if (lowerSni.contains("facebook") ||
            lowerSni.contains("fbcdn") ||
            lowerSni.contains("fb.com") ||
            lowerSni.contains("fbsbx") ||
            lowerSni.contains("meta.com")) {
            return FACEBOOK;
        }

        // 4. Instagram
        if (lowerSni.contains("instagram") ||
            lowerSni.contains("cdninstagram")) {
            return INSTAGRAM;
        }

        // 5. WhatsApp
        if (lowerSni.contains("whatsapp") ||
            lowerSni.contains("wa.me")) {
            return WHATSAPP;
        }

        // 6. Twitter/X
        if (lowerSni.contains("twitter") ||
            lowerSni.contains("twimg") ||
            lowerSni.contains("x.com") ||
            lowerSni.contains("t.co")) {
            return TWITTER;
        }

        // 7. Netflix
        if (lowerSni.contains("netflix") ||
            lowerSni.contains("nflxvideo") ||
            lowerSni.contains("nflximg")) {
            return NETFLIX;
        }

        // 8. Amazon
        if (lowerSni.contains("amazon") ||
            lowerSni.contains("amazonaws") ||
            lowerSni.contains("cloudfront") ||
            lowerSni.contains("aws")) {
            return AMAZON;
        }

        // 9. Microsoft
        if (lowerSni.contains("microsoft") ||
            lowerSni.contains("msn.com") ||
            lowerSni.contains("office") ||
            lowerSni.contains("azure") ||
            lowerSni.contains("live.com") ||
            lowerSni.contains("outlook") ||
            lowerSni.contains("bing")) {
            return MICROSOFT;
        }

        // 10. Apple
        if (lowerSni.contains("apple") ||
            lowerSni.contains("icloud") ||
            lowerSni.contains("mzstatic") ||
            lowerSni.contains("itunes")) {
            return APPLE;
        }

        // 11. Telegram
        if (lowerSni.contains("telegram") ||
            lowerSni.contains("t.me")) {
            return TELEGRAM;
        }

        // 12. TikTok
        if (lowerSni.contains("tiktok") ||
            lowerSni.contains("tiktokcdn") ||
            lowerSni.contains("musical.ly") ||
            lowerSni.contains("bytedance")) {
            return TIKTOK;
        }

        // 13. Spotify
        if (lowerSni.contains("spotify") ||
            lowerSni.contains("scdn.co")) {
            return SPOTIFY;
        }

        // 14. Zoom
        if (lowerSni.contains("zoom")) {
            return ZOOM;
        }

        // 15. Discord
        if (lowerSni.contains("discord") ||
            lowerSni.contains("discordapp")) {
            return DISCORD;
        }

        // 16. GitHub
        if (lowerSni.contains("github") ||
            lowerSni.contains("githubusercontent")) {
            return GITHUB;
        }

        // 17. Cloudflare
        if (lowerSni.contains("cloudflare") ||
            lowerSni.contains("cf-")) {
            return CLOUDFLARE;
        }

        // If SNI is present but not recognized, still mark as HTTPS/TLS
        return HTTPS;
    }
}
