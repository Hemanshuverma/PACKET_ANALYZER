package com.dpi.model;

/**
 * Enumeration of recognized application/protocol types.
 * Mapped from SNI or destination port information.
 */
public enum AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    GOOGLE,
    YOUTUBE,
    FACEBOOK,
    INSTAGRAM,
    TWITTER,
    AMAZON,
    NETFLIX,
    GITHUB,
    DISCORD,
    ZOOM,
    TELEGRAM,
    TIKTOK,
    SPOTIFY,
    CLOUDFLARE,
    MICROSOFT,
    APPLE;

    /**
     * Map an SNI hostname to an AppType.
     */
    public static AppType fromSni(String sni) {
        if (sni == null || sni.isEmpty()) return UNKNOWN;
        String lower = sni.toLowerCase();

        if (lower.contains("youtube"))      return YOUTUBE;
        if (lower.contains("facebook"))     return FACEBOOK;
        if (lower.contains("instagram"))    return INSTAGRAM;
        if (lower.contains("amazon"))       return AMAZON;
        if (lower.contains("netflix"))      return NETFLIX;
        if (lower.contains("github"))       return GITHUB;
        if (lower.contains("discord"))      return DISCORD;
        if (lower.contains("zoom"))         return ZOOM;
        if (lower.contains("telegram"))     return TELEGRAM;
        if (lower.contains("tiktok"))       return TIKTOK;
        if (lower.contains("spotify"))      return SPOTIFY;
        if (lower.contains("cloudflare"))   return CLOUDFLARE;
        if (lower.contains("microsoft"))    return MICROSOFT;
        if (lower.contains("apple"))        return APPLE;
        if (lower.contains("twitter") || lower.contains("t.co")) return TWITTER;
        if (lower.contains("google"))       return GOOGLE;

        return HTTPS; // default for any other TLS traffic
    }

    /**
     * Map a destination port to a basic AppType (pre-SNI classification).
     */
    public static AppType fromPort(int dstPort, int protocol) {
        if (protocol == 17 && dstPort == 53) return DNS;
        if (dstPort == 80)  return HTTP;
        if (dstPort == 443) return HTTPS;
        return UNKNOWN;
    }
}
