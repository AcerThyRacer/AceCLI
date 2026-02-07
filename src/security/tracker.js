// ============================================================
//  AceCLI – Mass Tracker Blocker
//  Blocks 500+ trackers, analytics, telemetry, and fingerprinting
// ============================================================
import chalk from 'chalk';

// ── Comprehensive Tracker Domain Blocklist ──────────────────
const TRACKER_DOMAINS = new Set([
  // Google tracking
  'google-analytics.com', 'www.google-analytics.com', 'ssl.google-analytics.com',
  'googletagmanager.com', 'www.googletagmanager.com', 'googletagservices.com',
  'googleadservices.com', 'www.googleadservices.com', 'googleads.g.doubleclick.net',
  'doubleclick.net', 'ad.doubleclick.net', 'static.doubleclick.net',
  'googleadservices.com', 'pagead2.googlesyndication.com', 'tpc.googlesyndication.com',
  'googlesyndication.com', 'adservice.google.com', 'adservice.google.ru',
  'partner.googleadservices.com', 'www.googletagservices.com',
  'firebase.google.com', 'firebaseanalytics.googleapis.com',
  'app-measurement.com', 'analytics.google.com', 'crashlytics.com',
  'crashlyticsreports-pa.googleapis.com', 'firebaseremoteconfig.googleapis.com',
  'googleapis.com', 'www.googleapis.com', 'logging.googleapis.com',

  // Facebook/Meta
  'connect.facebook.net', 'facebook.com', 'www.facebook.com', 'graph.facebook.com',
  'facebook-web-clients.appspot.com', 'fbcdn.net', 'staticxx.facebook.com',
  'analytics.facebook.com', 'pixel.facebook.com', 'events.reddit.com',
  'pixel.facebook.com', 'analytics.facebook.com', 'tr.facebook.com',
  'facebook-web-clients.appspot.com', 'instagram.com', 'www.instagram.com',
  'graph.instagram.com', 'i.instagram.com', 'cdninstagram.com',
  'whatsapp.com', 'web.whatsapp.com', 'mmg.whatsapp.net',

  // Microsoft
  'telemetry.microsoft.com', 'watson.telemetry.microsoft.com',
  'vortex.data.microsoft.com', 'settings-win.data.microsoft.com',
  'telemetry.urs.microsoft.com', 'diagnostics.support.microsoft.com',
  'corp.sts.microsoft.com', 'stats.microsoft.com', 'browser.events.data.microsoft.com',
  'bingapis.com', 'bing.com', 'www.bing.com', 'c.bing.com', 'bat.bing.com',
  'clarity.ms', 'www.clarity.ms', 'www.clarity.ms/s/0.7.16/clarity.js',
  'analytics.live.com', 'analytics.windowsazure.com',

  // Amazon/AWS tracking
  'amazon-adsystem.com', 'aax.amazon-adsystem.com', 'c.amazon-adsystem.com',
  's.amazon-adsystem.com', 'z-na.amazon-adsystem.com',
  'aws.demdex.net', 'amazonclix.com', 'assoc-amazon.com',
  'amazontrust.com', 'awsstatic.com', 'cloudfront-labs.amazonaws.com',
  'telemetry.amazonaws.com', 'metrics.amazonaws.com',

  // Adobe
  'omtrdc.net', 'omniture.com', '2o7.net', 'demdex.net', 'everesttech.net',
  'audiencemanager.de', 'dpm.demdex.net', 'cm.everesttech.net',
  'assets.adobedtm.com', 'satelliteLib.js', 'marketing.adobe.com',

  // Analytics platforms
  'segment.io', 'cdn.segment.com', 'api.segment.io', 'api.segment.com',
  'mixpanel.com', 'cdn.mxpnl.com', 'api.mixpanel.com', 'mixpanel.com/track',
  'amplitude.com', 'cdn.amplitude.com', 'api.amplitude.com', 'api2.amplitude.com',
  'amplitude.com', 'api.amplitude.com', 'amplitude.com/api',
  'hotjar.com', 'static.hotjar.com', 'script.hotjar.com', 'in.hotjar.com',
  'hotjar.io', 'vars.hotjar.com', 'identify.hotjar.com', 'careers.hotjar.com',
  'heap.io', 'cdn.heapanalytics.com', 'heapanalytics.com', 'api.heapanalytics.com',
  'fullstory.com', 'edge.fullstory.com', 'rs.fullstory.com', 'www.fullstory.com',
  'logrocket.com', 'cdn.logrocket.io', 'r.logrocket.io', 'cdn.lr-ingest.io',
  'datadoghq.com', 'browser-intake-datadoghq.com', 'rum.browser-intake-datadoghq.com',
  'newrelic.com', 'js-agent.newrelic.com', 'bam.nr-data.net', 'beacon-1.newrelic.com',
  'sentry.io', 'browser.sentry-cdn.com', 'o00000.ingest.sentry.io',
  'bugsnag.com', 'cdn.bugsnag.com', 'sessions.bugsnag.com', 'notify.bugsnag.com',
  'raygun.io', 'cdn.raygun.io', 'api.raygun.io',
  'rollbar.com', 'cdn.rollbar.com', 'api.rollbar.com', 'api.rollbar.js',
  'airbrake.io', 'cdn.airbrake.io', 'notifier-configs.airbrake.io',
  'pendo.io', 'cdn.pendo.io', 'app.pendo.io', 'data.pendo.io',
  'intercom.io', 'widget.intercom.io', 'api.intercom.io', 'js.intercomcdn.com',
  'n.rumble.com', 'plausible.io', 'plausible.analytics.com', 'analytics.plausible.io',
  'simpleanalytics.io', 'scripts.simpleanalyticscdn.com', 'queue.simpleanalyticscdn.com',
  'umami.is', 'analytics.umami.is', 'api.umami.dev',
  'cloudflareinsights.com', 'static.cloudflareinsights.com', 'beacon.cloudflare.com',
  'cloudflare.com', 'cloudflare-eth.com', 'cloudflare-dns.com', 'cdnjs.cloudflare.com',

  // Ad networks
  'adsystem.amazon.com', 'googleads.g.doubleclick.net', 'adnxs.com', 'ib.adnxs.com',
  'adsrvr.org', 'doubleverify.com', 'tags.t.doubleclick.net', 'pubmatic.com', 'hbopenbid.pubmatic.com',
  'openx.net', 'us-u.openx.net', 'ads.yieldmo.com', 'yieldmo.com', 'smaato.net', 'smaato.com',
  'moatads.com', 'z.moatads.com', 'ml314.com', 'ads.linkedin.com', 'analytics.linkedin.com',
  'bat.bing.com', 'criteo.com', 'casalemedia.com', 'rubiconproject.com', 'fastlane.rubiconproject.com',
  'advertising.com', 'adsymptotic.com', 'outbrain.com', 'taboola.com', 'taboola.net',
  'taboola.com', 'cdn.taboola.com', 'trc.taboola.com', 'api.taboola.com', 'impr.taboola.com',
  'revcontent.com', 'cdn.revcontent.com', 'widget-pixels.revcontent.com',

  // Social media
  'platform.twitter.com', 'analytics.twitter.com', 'static.ads-twitter.com',
  'syndication.twitter.com', 'cdn.syndication.twimg.com', 'p.twitter.com',
  'widgets.pinterest.com', 'log.pinterest.com', 'trk.pinterest.com', 'ct.pinterest.com',
  'analytics.pinterest.com', 'widgets.reddit.com', 'alb.reddit.com', 'pixel.reddit.com',
  'events.reddit.com', 'events.redditmedia.com', 'tiktok.com', 'analytics.tiktok.com',
  'ads.tiktok.com', 'business-api.tiktok.com', 'snapchat.com', 'tr.snapchat.com',
  'sc-analytics.appspot.com', 'analytics.snapchat.com', 'ads.snapchat.com',
  'linkedin.com', 'px.ads.linkedin.com', 'analytics.linkedin.com', 'dc.ads.linkedin.com',
  'lnkd.in', 'snap.licdn.com', 'platform.linkedin.com', 'youtube.com', 's.ytimg.com',
  'clients6.google.com', 'youtube-nocookie.com', 'ytimg.com', 'i9.ytimg.com',

  // TikTok
  'byteoversea.com', 'ibytedtos.com', 'musical.ly', 'tiktokv.com', 'tiktokcdn.com',
  'mon.byteoversea.com', 'mcs-sg.tiktok.com', 'mcs-va.tiktok.com',
  't.tiktok.com', 'analytics.tiktok.com', 'ads.tiktok.com',

  // Chinese tracking (Baidu, etc)
  'hm.baidu.com', 'baidu.com', 'hmma.baidu.com', 'push.zhanzhang.baidu.com',
  'pos.baidu.com', 'hm.baidu.com/hm.js', 'alog.umeng.com', 'umeng.com',
  'umengcloud.com', 'uop.umeng.com', 'cnzz.com', 's95.cnzz.com', 's4.cnzz.com',
  'cnzz.mmstat.com', 'mmstat.com', 'log.mmstat.com', 'ac.mmstat.com',

  // Russian tracking
  'mc.yandex.ru', 'yandex.ru', 'yandex.com', 'yandex.st', 'yandex.net',
  'metrica.yandex.com', 'metrika.yandex.ru', 'an.yandex.ru', 'adsdk.yandex.ru',
  'vk.com', 'vk.ru', 'st.mycdn.me', 'mycdn.me', 'tns-counter.ru', 'top-fwz1.mail.ru',
  'top.mail.ru', 'mail.ru', 'im.mail.ru', 'ad.mail.ru', 'target.mail.ru',
  'ok.ru', 'odnoklassniki.ru', 'an.yandex.ru',

  // Gaming/Unity/Epic
  'unity3d.com', 'adserver.unityads.unity3d.com', 'auction.unityads.unity3d.com',
  'config.unityads.unity3d.com', 'stats.unity3d.com', 'api.uca.cloud.unity3d.com',
  'tracking.epicgames.com', 'metrics.ol.epicgames.com', 'epicgames.com',
  'fortnite.com', 'fnapi.io', 'samsungosp.com', 'samsung-com.112.2o7.net',
  'analytics.mobile.yandex.net', 'appmetrica.yandex.com', 'mtalk.google.com',

  // Mobile/carrier analytics
  'inmobi.com', 'api.inmobi.com', 'sdkm.w.inmobi.com', 'appnext.com', 'admin.appnext.com',
  'flurry.com', 'data.flurry.com', 'ads.flurry.com', 'devs.flurry.com', 'api.flurry.com',
  'crashlytics.com', 'e.crashlytics.com', 'reports.crashlytics.com', 'settings.crashlytics.com',
  'app-measurement.com', 'app-analytics-services-att.com', 'att-analytics.com',
  'mobileanalytics.amazonaws.com', 'pinpoint.us-east-1.amazonaws.com',
  'mobileanalytics.us-east-1.amazonaws.com', 'device-messaging.us-east-1.amazonaws.com',
  'device-metrics-us.amazon.com', 'mobileanalytics.us-west-2.amazonaws.com',

  // VPN/App tracking
  'adjust.com', 'app.adjust.com', 'app.adjust.net.in', 'app.adjust.world',
  'adjust.io', 'adeven.com', 'adjust.io', 'control.kochava.com', 'web.kochava.com',
  'kochava.com', 'kvinit-prod.api.kochava.com', 'web-vitals.kochava.com',
  'appsflyer.com', 'events.appsflyer.com', 'conversions.appsflyer.com', 't.appsflyer.com',
  'stats.appsflyer.com', 'api.appsflyer.com', 'skadnetwork.appsflyer.com',
  'branch.io', 'api.branch.io', 'api2.branch.io', 'cdn.branch.io', 'grow.branch.io',
  'tenjin.io', 'track.tenjin.io', 'devtrack.tenjin.io', 'reports.tenjin.io',
  'singular.net', 'sdk-api.singular.net', 'i.singular.net', 's2s.singular.net',
  'start.io', 'init.start.io', 'req.start.io', 'srv.start.io', 'track.start.io',
  'fyber.com', 'engine.fyber.com', 'video.fyber.com', 'rewarded-video.fyber.com',
  'mopub.com', 'ads.mopub.com', 'analytics.mopub.com', 'api.mopub.com', 'web.mopub.com',
  'chartboost.com', 'live.chartboost.com', 'analytics.chartboost.com', 'api.chartboost.com',
  'adcolony.com', 'ads30.adcolony.com', 'androidads23.adcolony.com', 'iosads24.adcolony.com',
  'vungle.com', 'api.vungle.com', 'cdn.vungle.com', 'ingest.vungle.com',
  'applovin.com', 'ms.applovin.com', 'rt.applovin.com', 'prod-a.applovin.com',
  'api.applovin.com', 'assets.applovin.com', 'events.applovin.com', 'ms4.applovin.com',
  'ironsrc.com', 'init.supersonicads.com', 'outcome.supersonicads.com', 'traffic.moonscoop.tv',
  'supersonicads.com', 'init.supersonicads.com', 'outcome.supersonicads.com',
  'tapjoy.com', 'ws.tapjoyads.com', 'placements.tapjoy.com', 'connect.tapjoy.com',
  'pubnative.net', 'api.pubnative.net', 'assets.pubnative.net', 'dts.pubnative.net',
  'hyprmx.com', 'ads.hyprmx.com', 'manifest.hyprmx.com', 'creditreporting.hyprmx.com',
  'adtiming.com', 'api.adtiming.com', 'ad.adtiming.com', 'tracker.adtiming.com',
  'fbpigeon.com', 'log.outbrain.com', 'widgets.outbrain.com', 'amplify.outbrain.com',
  'outbrainimg.com', 'paid.outbrain.com', 'tr.outbrain.com', 'images.outbrain.com',
  'zemanta.com', 'dsp.zemanta.com', 'api.zemanta.com', 'exchange.zemanta.com',
  'rtbtrack.io', 'pixel.rtbtrack.io', 'tracker.rtbtrack.io', 'track.rtbtrack.io',
  'liftoff.io', 'impression.link', 'click.liftoff.io', 'track.liftoff.io',
  'pangle.io', 'pangleglobal.com', 'api-adservices.apple.com', 'iadsdk.apple.com',
  'google-analytics.com', 'ssl.google-analytics.com', 'googleadservices.com',
  'googleoptimize.com', 'googletagmanager.com', 'googletagservices.com', 'gstatic.com',

  // Other major trackers
  'quantserve.com', 'pixel.quantserve.com', 'secure.quantserve.com', 'rules.quantcount.com',
  'scorecardresearch.com', 'sa.scorecardresearch.com', 'sb.scorecardresearch.com',
  'comscore.com', 'appscore.comscore.com', 'comscoredatagems.com',
  'nielsen.com', 'imrworldwide.com', 'secure-dcr.imrworldwide.com', 'secure-us.imrworldwide.com',
  'krxd.net', 'beacon.krxd.net', 'cdn.krxd.net', 'consumer.krxd.net',
  'exelator.com', 'loadm.exelator.com', 'load.exelator.com', 'dyn.beap.ad.yieldmanager.net',
  'yieldmanager.net', 'yieldmanager.com', 'ad.yieldmanager.com',
  'mathtag.com', 'sync.mathtag.com', 'pixel.mathtag.com', 'image2.pubmatic.com',
  'ads.pubmatic.com', 'gads.pubmatic.com', 'hbopenbid.pubmatic.com', 'showads.pubmatic.com',
  'contextweb.com', 'bh.contextweb.com', 'tag.contextweb.com', 'rt.udmserve.net',
  'udmserve.net', 'ssp.udmserve.net', 'cdn.udmserve.net',
  'dotomi.com', 'proc.ad.cpe.dotomi.com', 'ad.cpe.dotomi.com', 'match.adsrvr.org',
  'adsrvr.org', 'ad.adsrvr.org', 'sync.adsrvr.org',
  'agkn.com', 'd.agkn.com', 'data.agkn.com', 'adaraanalytics.com', 'api.adaraanalytics.com',
  'deepintent.com', 'api.deepintent.com', 'cdn.deepintent.com',
  'eyeota.net', 'ps.eyeota.net', 'sync.eyeota.net', 'dsp.eyeota.net',
  'crwdcntrl.net', 'bcp.crwdcntrl.net', 'tag.crwdcntrl.net', 'ad.crwdcntrl.net',
  '33across.com', 'ssc.33across.com', 'dp2.33across.com', 'lexicon.33across.com',
  'sharethrough.com', 'match.sharethrough.com', 'dsp.sharethrough.com', 'btlr.sharethrough.com',
  'addthis.com', 's7.addthis.com', 'm.addthis.com', 's.addthisedge.com',
  'addthisedge.com', 'x.dlx.addthis.com', 'e.dlx.addthis.com', 'acdn.adnxs.com',
  'adnxs.com', 'nym1.b.adnxs.com', 'secure.adnxs.com', 'ib.adnxs.com',
  'openx.net', 'us-u.openx.net', 'uk-u.openx.net', 'eu-u.openx.net',
  'bid.openx.net', 'rmgdsp-asia.openx.net', 'u.openx.net', 'track.openx.net',
  'pubmatic.com', 'image4.pubmatic.com', 'image6.pubmatic.com', 'simage4.pubmatic.com',
  'rtbidhost.pubmatic.com', 'track.pubmatic.com', 'ads.pubmatic.com',
  'rubiconproject.com', 'fastlane.rubiconproject.com', 'eus.rubiconproject.com',
  'prebid-server.rubiconproject.com', 'tap.rubiconproject.com', 'pixel.rubiconproject.com',
  'amazon-adsystem.com', 'aax.amazon-adsystem.com', 's.amazon-adsystem.com',
  'c.amazon-adsystem.com', 'z-na.amazon-adsystem.com', 'fls-na.amazon-adsystem.com',
  'wms.assoc-amazon.com', 'assoc-amazon.com', 'ws-na.amazon-adsystem.com',
  'casalemedia.com', 'ssum.casalemedia.com', 'dsum.casalemedia.com',
  'as.casalemedia.com', 'js.casalemedia.com', 'dsum-sec.casalemedia.com',
  'indexww.com', 'cm.indexww.com', 'ht.indexww.com', 'as-sec.casalemedia.com',
  'gumgum.com', 'g2.gumgum.com', 'js.gumgum.com', 'ads.gumgum.com',
  'onetag-sys.com', 'get.onetag.com', 'tags.onetag.com', 'onetag.io',
  'sovrn.com', 'ap.lijit.com', 'advcapture.lijit.com', 'ld.send.microad.jp',
  'microad.jp', 'dsp.send.microad.jp', 'tr.microad.jp', 'aid.send.microad.jp',
  'verve.com', 'ads.undertone.com', 'ads.undertone.com', 'cdn.undertone.com',
  'underdog.media', 'bid.underdog.media', 'udmserve.net', 'ssp.udmserve.net',
  'connatix.com', 'cdn.connatix.com', 'api.connatix.com', 'triggers.wfxtriggers.com',
  'wfxtriggers.com', 'c.wfxtriggers.com', 'i.wfxtriggers.com',
  'spotxchange.com', 'search.spotxchange.com', 'sync.search.spotxchange.com',
  'sync.spotx.tv', 'spotx.tv', 'cdn.spotxcdn.com', 'search.spotxchange.com',
  'tremorhub.com', 'adserver.tremorhub.com', 'cdn.tremorhub.com', 'sodar.google.com',
  'brightcove.com', 'metrics.brightcove.com', 'edge.api.brightcove.com',
  'akamaihd.net', 'players.akamai.net', 'images.akamai.net',
  'liadm.com', 'i.liadm.com', 'p.liadm.com', 's.liadm.com', 'idx.liadm.com',
  'media.net', 'cdna.media.net', 'static.media.net', 'ads.media.net',
  's-onetag.com', 'get.s-onetag.com', 'signal-beacon.s-onetag.com', 'onetag.io',
  'neustar.biz', 'aa.agkn.com', 'agkn.com', 'federatedmedia.net',
  'brealtime.com', 'bid.brealtime.com', 'js.brealtime.com', 'ads.brealtime.com',
  'optimatic.com', 'mgid.com', 'servicer.mgid.com', 'jsc.mgid.com', 'cdn.mgid.com',
  'teads.tv', 'cdn.teads.tv', 'a.teads.tv', 'sync.teads.tv', 'p.teads.tv',
  'innovid.com', 'ag.innovid.com', 's.innovid.com', 'dts.innovid.com',
  'freewheel.tv', 'ads.stickyadstv.com', 'ads.freewheel.tv',
  'smartadserver.com', 'prg.smartadserver.com', 'ak-ns.sascdn.com', 'ced.sascdn.com',
  'rtb-csync.smartadserver.com', 'diff.smartadserver.com',
  'revcontent.com', 'cdn.revcontent.com', 'img.revcontent.com',
  'labs-cdn.revcontent.com', 'trends.revcontent.com',
  'taboola.com', 'trc.taboola.com', 'cdn.taboola.com', 'api.taboola.com', 'impr.taboola.com',
  'outbrain.com', 'widgets.outbrain.com', 'paid.outbrain.com', 'amplify.outbrain.com',
  'tr.outbrain.com', 'sync.outbrain.com', 'odb.outbrain.com',

  // IoT/Smart device telemetry
  'smartscreen.microsoft.com', 'smartscreen-prod.microsoft.com',
  'wdcp.microsoft.com', 'wdcpalt.microsoft.com',
  'msnbot-65-55-108-23.search.msn.com',

  // Browser telemetry
  'safebrowsing.googleapis.com', 'safebrowsing-cache.google.com',
  'shavar.services.mozilla.com', 'tracking-protection.cdn.mozilla.net',
  'firefox.settings.services.mozilla.com', 'content-signature-2.cdn.mozilla.net',
  'telemetry.mozilla.org', 'incoming.telemetry.mozilla.org', 'data.mozilla.com',

  // OS-level telemetry
  'settings-win.data.microsoft.com', 'vortex-win.data.microsoft.com',
  'win10.ipv6.microsoft.com', 'teredo.ipv6.microsoft.com',
  'watson.microsoft.com', 'oca.telemetry.microsoft.com',
  'ceuswatcab01.blob.core.windows.net', 'ceuswatcab02.blob.core.windows.net',

  // Apple telemetry
  'metrics.apple.com', 'supportmetrics.apple.com', 'xp.apple.com',
  'xp.itunes-apple.com.akadns.net', 'axm-adm-mavenhub.xhome.apple.com',

  // Discord tracking
  'discord.com', 'cdn.discordapp.com', 'gateway.discord.gg',
  'discordapp.com', 'discord.gg', 'discord.media', 'discordapp.net',

  // Spotify tracking
  'spclient.wg.spotify.com', 'heads-ak-spotify-com.akamaized.net',
  'apresolve.spotify.com', 'dealer.spotify.com', 'telemetry.spotify.com',

  // Netflix tracking
  'nrdp.nccp.netflix.com', 'ichnaea.netflix.com', 'appboot.netflix.com',

  // Various fingerprinting
  'fingerprintjs.com', 'fpjs.io', 'openfpcdn.io', 'cdn.fpjs.io',
  'cadmus.script.ac', 'script.ac', 'px.spiceworks.com', 'pixel.condenastdigital.com',
  'rum.optimizely.com', 'log.optimizely.com', 'cdn.optimizely.com',
  'optimizely.com', 'cdn-pci.optimizely.com', 'cdn.optimizely.com',

  // Survey/Feedback trackers
  'surveymonkey.com', 'www.surveymonkey.com', 'widget.surveymonkey.com',
  'siteintercept.qualtrics.com', 'zn3qgs0p5juktrcy1-qualtrics.siteintercept.qualtrics.com',
  'qualtrics.com', 'fullstory.com', 'edge.fullstory.com', 'rs.fullstory.com',

  // More miscellaneous trackers
  'luckyorange.com', 'cdn.luckyorange.com', 'w1.luckyorange.com',
  'crazyegg.com', 'script.crazyegg.com', 'dnn506yrbagrg.cloudfront.net',
  'userreplay.net', 'cdn.userreplay.net', 's3.amazonaws.com/userreplay',
  'sessioncam.com', 'ws.sessioncam.com', 'cdn.sessioncam.com',
  'inspectlet.com', 'cdn.inspectlet.com', 'www.inspectlet.com',
  'mouseflow.com', 'cdn.mouseflow.com', 'tools.mouseflow.com',
  'freshmarketer.com', 'cdn.freshmarketer.com', 'claritybt.freshmarketer.com',
  're-invigorate.net', 'include.reinvigorate.net', 'reinvigorate.net',
  'visualwebsiteoptimizer.com', 'dev.visualwebsiteoptimizer.com',
  'cdn.vwo.com', 'dacdn.vwo.com', 'dev.visualwebsiteoptimizer.com',
  'goptimize.com', 'www.googleoptimize.com',
  'pingdom.net', 'rum-static.pingdom.net', 'rum-collector-2.pingdom.net',
  'gtmetrix.com', 'www.gtmetrix.com',
  'speedcurve.com', 'cdn.speedcurve.com', 'lux.speedcurve.com',
  'fingerprintjs.com', 'cdn.fingerprintjs.com', 'fpjs.io', 'cdn.fpjs.io',
  'perimeterx.net', 'client.perimeterx.net', 'collector.perimeterx.net',
  'datadome.co', 'api-js.datadome.co', 'js.datadome.co', 'api.datadome.co',
  ' Kasada.io', 'i.kasada.io', 'c.kasada.io', 'api.kasada.io',
  'imperva.com', 'www.imperva.com', 'nsg.corporate.imperva.com',
  'distilnetworks.com', 'www.distilnetworks.com',
  'whiteops.com', 'tags.whiteops.com', 'static.whiteops.com',
  'adform.net', 's1.adform.net', 'adx.adform.net', 'cm.adform.net',
  'bidtheatre.com', 'match.adsby.bidtheatre.com', 'www.bidtheatre.com',
  'adition.com', 'imagesrv.adition.com', 'ad1.adition.net',
  'adition.net', 'dsp.adfarm1.adition.com', 'ad2.adfarm1.adition.com',
  'bidder.criteo.com', 'gum.criteo.com', 'rtax.criteo.com', 'dis.criteo.com',
  'criteo.net', 'static.criteo.net', 'sslwidget.criteo.com', 'widget.criteo.com',
  'criteo.com', 'bidder.criteo.com', 'rtax.criteo.com', 'gum.criteo.com',
  'criteo.net', 'sslwidget.criteo.net', 'widget.criteo.net',
  'rlcdn.com', 'idsync.rlcdn.com', 'rc.rlcdn.com', 'ei.rlcdn.com',
  'tribalfusion.com', 'a.tribalfusion.com', 'cdns.tribalfusion.com',
  'media6degrees.com', 'tag.media6degrees.com', 'ad.media6degrees.com',
  'turn.com', 'ad.turn.com', 'd.turn.com', 'r.turn.com',
  'xplusone.com', 'pxl.iqity.com', 'pt.xplusone.com',
  'adap.tv', 'sync.adap.tv', 'video.adaptv.advertising.com',
  'adsymptotic.com', 'p.adsymptotic.com', 'api.adsymptotic.com',
  'mookie1.com', 'odr.mookie1.com', 't.mookie1.com', 'rm.mookie1.com',
  'myvisualiq.net', 't.myvisualiq.net', 'p.myvisualiq.net',
  'nexac.com', 'p.nexac.com', 'r.nexac.com', 'h.nexac.com',
  'bluekai.com', 'tags.bluekai.com', 'stags.bluekai.com',
  'bkrtx.com', 'tags.bkrtx.com', 'stags.bkrtx.com',
  'oracle.com', 'tags.oracle.com', 'analytics.oracle.com',
  'en25.com', 's4384.t.en25.com', 'img.en25.com',
  'eloqua.com', 's1795.t.eloqua.com', 'img.en25.com',
  'marketo.net', 'munchkin.marketo.net', 'marketo.com', 'marketo.net',
  'pardot.com', 'pi.pardot.com', 'tracker.pardot.com', 'go.pardot.com',
  'salesforce.com', 'cdn.pardot.com', 'tracker.salesforce.com',
  'force.com', 'secure.force.com', 'analytics.force.com',
  'eloqua.com', 's', 't.eloqua.com', 'img.en25.com',
  'eloquaeditors.com', 'eloquaeditors.com', 'assets.eloqua.com',
  'bizible.com', 'cdn.bizible.com', 'log.bizible.com', 'cdn.bizibly.com',
  'bizibly.com', 'cdn.bizibly.com',
  'actonsoftware.com', 'cid.actonsoftware.com', 'pi.actonsoftware.com',
  'actonsoftware.com', 'marketing.actonsoftware.com',
  'hubspot.com', 'js.hs-analytics.net', 'js.hs-scripts.com',
  'hs-analytics.net', 'hs-scripts.com', 'forms.hubspot.com',
  'api.hubapi.com', 'track.hubspot.com', 'events.hubspot.com',
  'getclicky.com', 'static.getclicky.com', 'in.getclicky.com',
  'statcounter.com', 'c.statcounter.com', 'www.statcounter.com',
  'histats.com', 'sstatic1.histats.com', 'histats.com',
  'reinvigorate.net', 'include.reinvigorate.net', 'reinvigorate.net',
  'woopra.com', 'static.woopra.com', 'www.woopra.com',
  'chartbeat.com', 'static.chartbeat.com', 'ping.chartbeat.net',
  'm.chartbeat.net', 'static.chartbeat.com', 'api.chartbeat.com',
  'parsely.com', 'static.parsely.com', 'srv.pixel.parsely.com',
  'd.parsely.com', 'cdn.parsely.com', 'api.parsely.com',
  'quantcast.com', 'pixel.quantserve.com', 'secure.quantserve.com',
  'quantcount.com', 'rules.quantcount.com', 'p.q-common-dev.qa1.quantcount.com',
  'scorecardresearch.com', 'sa.scorecardresearch.com', 'sb.scorecardresearch.com',
  'scorecardresearch.com', 'sa.scorecardresearch.com', 'sb.scorecardresearch.com',
  'comscore.com', 'appscore.comscore.com', 'comscoredatagems.com',
  'nielsen-online.com', 'secure-dcr.imrworldwide.com', 'secure-us.imrworldwide.com',
  'imrworldwide.com', 'secure-dcr.imrworldwide.com', 'secure-us.imrworldwide.com',
  'effectivemeasure.net', 'me.effectivemeasure.net', 'collector.effectivemeasure.net',
  'certifica.com', 'ads.certifica.com', 'pixel.certifica.com',
  'mxpnl.com', 'cdn.mxpnl.com', 'cdn4.mxpnl.com',
  'mixpanel.com', 'api.mixpanel.com', 'decide.mixpanel.com',
  'amplitude.com', 'cdn.amplitude.com', 'api.amplitude.com', 'api2.amplitude.com',
  'segment.com', 'cdn.segment.com', 'api.segment.io', 'cdn.segment.io',
  'segment.io', 'cdn.segment.io', 'api.segment.io',
  'kissmetrics.com', 'doug1izaerwt3.cloudfront.net', 'i.kissmetrics.com',
  'kissmetrics.com', 'doug1izaerwt3.cloudfront.net', 'i.kissmetrics.com',
  'heapanalytics.com', 'cdn.heapanalytics.com', 'heapanalytics.com',
  'cdn.heapanalytics.com', 'heapanalytics.com', 'api.heapanalytics.com',
  'keen.io', 'api.keen.io', 'd26b395fwzu5fz.cloudfront.net',
  'gosquared.com', 'd1l6p2sc9645hc.cloudfront.net', 'data.gosquared.com',
  'chartbeat.com', 'static.chartbeat.com', 'ping.chartbeat.net',
  'm.chartbeat.net', 'static.chartbeat.com', 'api.chartbeat.com',
  'omtrdc.net', 'omniture.com', '2o7.net', 'demdex.net',
  'everesttech.net', 'audiencemanager.de', 'dpm.demdex.net',
  'cm.everesttech.net', 'assets.adobedtm.com', 'satelliteLib.js',
  'marketing.adobe.com', 'librato.com', 'metrics-api.librato.com',
  'librato.com', 'metrics-api.librato.com', 'cdn.librato.com',
  'datadoghq.com', 'browser-intake-datadoghq.com', 'rum.browser-intake-datadoghq.com',
  'newrelic.com', 'js-agent.newrelic.com', 'bam.nr-data.net',
  'sentry.io', 'browser.sentry-cdn.com', 'o00000.ingest.sentry.io',
  'bugsnag.com', 'cdn.bugsnag.com', 'sessions.bugsnag.com',
  'raygun.io', 'cdn.raygun.io', 'api.raygun.io', 'raygun.io',
  'rollbar.com', 'cdn.rollbar.com', 'api.rollbar.com', 'rollbar.js',
  'airbrake.io', 'cdn.airbrake.io', 'notifier-configs.airbrake.io',
  'honeybadger.io', 'js.honeybadger.io', 'api.honeybadger.io',
  'honeybadger.io', 'js.honeybadger.io', 'api.honeybadger.io',
  'trackjs.com', 'cdn.trackjs.com', 'capture.trackjs.com', 'usage.trackjs.com',
  'loggly.com', 'logs-01.loggly.com', 'cloudfront.loggly.com',
  'logentries.com', 'js.logentries.com', 'api.logentries.com',
  'sumologic.com', 'collectors.sumologic.com', 'endpoint1.collection.us2.sumologic.com',
  'splunk.com', 'input.splunk.com', 'hec.splunk.com',
  'elastic.co', 'cluster-001.elasticsearch.org', 'apm-server.elastic.co',
  'grafana.com', 'stats.grafana.org', 'grafana.com',
  'prometheus.io', 'prometheus.io', 'pushgateway.prometheus.io',
  'influxdata.com', 'influxdb.com', 'metrics.influxdata.com',
  'sysdig.com', 'collector.sysdigcloud.com', 'app.sysdigcloud.com',
  'dynatrace.com', 'dynatrace.com', 'tenant.dynatrace.com', 'activegate.dynatrace.com',
  'appdynamics.com', 'controller.appdynamics.com', 'api.appdynamics.com',
  'instana.io', 'eum.instana.io', 'agent.instana.io',
  'scoutapm.com', 'apm.scoutapp.com', 'scoutapm.com',
  'skylight.io', 'www.skylight.io', 'agent.skylight.io',
  'appsignal.com', 'appsignal.com', 'push.appsignal.com',
  'honeycomb.io', 'api.honeycomb.io', 'ui.honeycomb.io',
  'lightstep.com', 'collector.lightstep.com', 'api.lightstep.com',
  'opentelemetry.io', 'otel-collector.io', 'opentelemetry.io',
  'jaegertracing.io', 'jaeger-agent.jaegertracing.io', 'jaeger-collector.jaegertracing.io',
  'zipkin.io', 'zipkin-server.zipkin.io', 'zipkin.io',
  'signalfx.com', 'ingest.signalfx.com', 'api.signalfx.com',
  'wavefront.com', 'metrics.wavefront.com', 'api.wavefront.com',
  'opsgenie.com', 'api.opsgenie.com', 'app.opsgenie.com',
  'pagerduty.com', 'events.pagerduty.com', 'api.pagerduty.com',
  'victorops.com', 'alert.victorops.com', 'api.victorops.com',
  'xmatters.com', 'company.xmatters.com', 'api.xmatters.com',
  'datadoghq.com', 'browser-intake-datadoghq.com', 'rum.browser-intake-datadoghq.com',
  'pingdom.com', 'rum.pingdom.net', 'stats.pingdom.com',
  'uptimerobot.com', 'api.uptimerobot.com', 'stats.uptimerobot.com',
  'statuspage.io', 'api.statuspage.io', 'statuspage.io',
  'healthchecks.io', 'hc-ping.com', 'healthchecks.io',
  'site24x7.com', 'stats.site24x7.com', 'api.site24x7.com',
  'freshping.io', 'api.freshping.io', 'stats.freshping.io',
  'sematext.com', 'spm-receiver.sematext.com', 'logsene-receiver.sematext.com',
  'logzio.com', 'listener.logz.io', 'api.logz.io',
  'papertrailapp.com', 'logs.papertrailapp.com', 'api.papertrailapp.com',
  'logdna.com', 'logs.logdna.com', 'api.logdna.com',
  'scalyr.com', 'www.scalyr.com', 'api.scalyr.com', 'logs.scalyr.com',
  'coralogix.com', 'api.coralogix.com', 'ingress.coralogix.com',
  'humio.com', 'cloud.humio.com', 'api.humio.com',
  'loki.io', 'loki.io', 'logs-prod-us-central1.grafana.net',
  'seq.com', 'datalust.co', 'seq.com', 'logs.datalust.co',
  'graylog.org', 'graylog.com', 'api.graylog.com', 'logs.graylog.org',
  'logstash.net', 'logstash.net', 'beats-api.logstash.net',
  'fluentd.org', 'fluentd.org', 'api.fluentd.org',
  'vector.dev', 'vector.dev', 'api.vector.dev',
  'telegraf.com', 'telegraf.io', 'api.telegraf.com',
  'promtail.io', 'promtail.io', 'api.promtail.io',
  'grafana.net', 'grafana.net', 'logs-prod.grafana.net',
  'betteruptime.com', 'betteruptime.com', 'api.betteruptime.com',
  'uptime.com', 'uptime.com', 'api.uptime.com',
  'cronitor.io', 'cronitor.io', 'api.cronitor.io',
  'deadmanssnitch.com', 'api.deadmanssnitch.com', 'deadmanssnitch.com',
  'sentry.io', 'browser.sentry-cdn.com', 'o00000.ingest.sentry.io',
  'glitchtip.com', 'glitchtip.com', 'api.glitchtip.com',
  'raygun.io', 'cdn.raygun.io', 'api.raygun.io', 'raygun.io',
  'honeybadger.io', 'js.honeybadger.io', 'api.honeybadger.io',
  'appsignal.com', 'appsignal.com', 'push.appsignal.com',
  'skylight.io', 'www.skylight.io', 'agent.skylight.io',
  'scoutapm.com', 'apm.scoutapp.com', 'scoutapm.com',
  'bugsnag.com', 'cdn.bugsnag.com', 'sessions.bugsnag.com',
  'airbrake.io', 'cdn.airbrake.io', 'notifier-configs.airbrake.io',
  'rollbar.com', 'cdn.rollbar.com', 'api.rollbar.com', 'rollbar.js',
  'logrocket.com', 'cdn.logrocket.io', 'r.logrocket.io', 'cdn.lr-ingest.io',
  'logdna.com', 'logs.logdna.com', 'api.logdna.com',
  'fullstory.com', 'edge.fullstory.com', 'rs.fullstory.com', 'www.fullstory.com',
  'heap.io', 'cdn.heapanalytics.com', 'heapanalytics.com', 'api.heapanalytics.com',
  'amplitude.com', 'cdn.amplitude.com', 'api.amplitude.com', 'api2.amplitude.com',
  'mixpanel.com', 'cdn.mxpnl.com', 'api.mixpanel.com', 'mixpanel.com/track',
  'kissmetrics.com', 'doug1izaerwt3.cloudfront.net', 'i.kissmetrics.com',
  'woopra.com', 'static.woopra.com', 'www.woopra.com',
  'gosquared.com', 'd1l6p2sc9645hc.cloudfront.net', 'data.gosquared.com',
  'clicky.com', 'static.getclicky.com', 'in.getclicky.com',
  'chartbeat.com', 'static.chartbeat.com', 'ping.chartbeat.net',
  'parsely.com', 'static.parsely.com', 'srv.pixel.parsely.com',
  'quantcast.com', 'pixel.quantserve.com', 'secure.quantserve.com',
  'comscore.com', 'appscore.comscore.com', 'comscoredatagems.com',
  'scorecardresearch.com', 'sa.scorecardresearch.com', 'sb.scorecardresearch.com',
  'nielsen.com', 'secure-dcr.imrworldwide.com', 'secure-us.imrworldwide.com',
  'effectivemeasure.net', 'me.effectivemeasure.net', 'collector.effectivemeasure.net',
  'alexa.com', 'd31qbv1cthcecs.cloudfront.net', 'www.alexa.com',
  'certifica.com', 'ads.certifica.com', 'pixel.certifica.com',
  'torbit.com', 'stats.torbit.com', 'torbit.com', 'api.torbit.com',
  'newrelic.com', 'js-agent.newrelic.com', 'bam.nr-data.net', 'beacon-1.newrelic.com',
  'datadoghq.com', 'browser-intake-datadoghq.com', 'rum.browser-intake-datadoghq.com',
  'dynatrace.com', 'dynatrace.com', 'tenant.dynatrace.com', 'activegate.dynatrace.com',
  'instana.io', 'eum.instana.io', 'agent.instana.io',
  'appdynamics.com', 'controller.appdynamics.com', 'api.appdynamics.com',
]);

// ── URL Tracking Parameters ─────────────────────────────────
const TRACKING_PARAMS = new Set([
  // Google UTM
  'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
  'utm_id', 'utm_source_platform', 'utm_creative_format', 'utm_marketing_tactic',

  // Facebook/Meta
  'fbclid', 'fb_action_ids', 'fb_action_types', 'fb_source', 'fb_ref',
  'fb_comment_id', 'fb_xd_fragment', 'fb_pipeline_cr', 'fb_instant_article',

  // Other social
  'twclid', 'ttclid', 'li_fat_id', 'mc_cid', 'mc_eid',
  'igshid', 'wickedid', 'yclid', 'gclid', 'gclsrc',
  'dclid', 'msclkid', 'zanpid', 'kenshoo', 'ef_id',

  // Affiliate/tracking
  'affid', 'afftrack', 'clickid', 'subid', 'ref', 'referrer',
  'referral', 'affiliate', 'affiliate_id', 'affiliateid', 'aff_id',
  'cid', 'pid', 'sid', 'tid', 'trk', 'track', 'tracking',
  'campaign', 'campaign_id', 'campaignid', 'cmp', 'cmpid',
  'source', 'src', 'origin', 'via', 'vendor', 'partner',

  // Email marketing
  'mtm_source', 'mtm_medium', 'mtm_campaign', 'mtm_keyword', 'mtm_content',
  'matomo_source', 'matomo_medium', 'matomo_campaign', 'matomo_keyword',
  'utm_email', 'email_id', 'emailid', 'eid', 'mailid',
  'memberid', 'subscriberid', 'recipient', 'recipient_id',

  // Misc
  'wtrid', 'wtmcid', 'wtm_source', 'wickedid',
  'hsa_cam', 'hsa_grp', 'hsa_mt', 'hsa_src', 'hsa_ad', 'hsa_acc', 'hsa_net',
  'hsa_kw', 'hsa_tgt', 'hsa_la', 'hsa_ol', 'hsa_ver', 'hsa_random',

  // Adobe
  's_cid', 's_kwcid', 's_kwid', 'ef_id',

  // Pinterest
  'epik', 'epikid',

  // TikTok
  '_t', '_type', 'traffic_type', 'share_app_id', 'share_author_id',
  'share_link_id', 'ug_source', 'ug_medium', 'ug_campaign',

  // Snapchat
  'sc_src', 'sc_content', 'sc_channel', 'sc_campaign', 'sc_creative',

  // Reddit
  'rdt_cid',

  // Apple
  'itsct', 'itscg', 'lsid', 'pt',

  // Microsoft
  'msclkid', 'cvid', 'oicd',

  // DoubleClick
  'dclid', 'dcid',

  // Amazon
  'ascsubtag', 'asc_refurl', 'asc_campaign', 'asc_source', 'asc_ref_tag',
  'ref_', 'refRID', 'qid', 'sr', 'keywords', 'sprefix', 'crid',
  'pd_rd_i', 'pd_rd_r', 'pd_rd_w', 'pd_rd_wg', 'pf_rd_p', 'pf_rd_r',
  'pd_rd_a', 'pf_rd_s', 'pf_rd_t', 'pf_rd_i', 'pf_rd_m',
  'psc', 'ie', 'node', 'smid', 'tag', 'linkId', 'linkCode',

  // eBay
  '_trkparms', '_trksid', '_from', '_nkw', '_sacat', '_sop', '_ipg',
  'campid', 'customid', 'mkevt', 'mkcid', 'mkrid', 'toolid',

  // YouTube
  'feature', 'app', 'ab_channel', 'si', 'pp', 't', 'start', 'end',
  'list', 'index', 'ab_brand',

  // Generic
  'click', 'clicked', 'from', 'to', 'redirect', 'redir', 'url',
  'return', 'returnUrl', 'return_to', 'next', 'destination',
  'token', 'auth', 'key', 'apikey', 'api_key', 'access_token',
  'session', 'sessionid', 'phid', 'vid', 'pid', 'sid',

  // Shopify
  'shpxid', 'shp', 'shpn', 'shpv', 'shp_r', 'shp_m',

  // HubSpot
  'hsCtaTracking', 'hs_a', 'hs_preview', 'hsCacheBuster',

  // Marketo
  'mkt_tok', 'mkt_tok2',

  // Eloqua
  'elqTrackId', 'elq', 'elqCampaignId',

  // Pardot
  'pi_campaign_id', 'pi_ad_id', 'pi_trk',

  // Crazy Egg
  'cerf', 'cerf1', '_ga', '_gid', '_gac', '_gat',

  // More Google Analytics
  '_ga', '_gid', '_gac', '_gat', '_gl', '_gcl', '_gcl_au', '_gcl_dc',
  '_gcl_aw', '_gcl_gb', '_gcl_gf',

  // Internal tracking
  'internal', 'internal_id', 'int', 'int_id', 'intsrc', 'int_source',
  'promo', 'promocode', 'promo_code', 'coupon', 'discount', 'deal',
  'offer', 'offers', 'sale', 'special', 'campaign_id', 'promotion',

  // Vercel
  'vercel', 'vercelAnalytics',

  // Netlify
  'nf_resize', 'nf_photo', 'nf_analytics',

  // Cloudflare
  'cf_chl_jschl_tk__', 'cf_chl_captcha_tk__', 'cf_chl_prog', '__cf_chl_jschl_tk__',
  '__cf_chl_captcha_tk__', '__cf_chl_prog', 'cf_use_ob', 'cf_ob_info', 'cf_ob',

  // Generic analytics
  'analytics', 'analytic', 'stats', 'stat', 'metrics', 'metric',
  'event', 'events', 'track', 'tracking', 'trk', 'trks',
  'beacon', 'beacons', 'ping', 'pings', 'log', 'logs',
  'visitor', 'visitors', 'visitor_id', 'visitorid', 'vid',
  'user', 'user_id', 'userid', 'uid', 'uuid', 'guid',
  'fingerprint', 'fp', 'device', 'device_id', 'deviceid',
  'browser', 'browser_id', 'session', 'session_id', 'sessionid',

  // Query sanitization
  'share', 'shared', 'sharing', 'sharer', 'sharetype',
  'invited_by', 'invitedby', 'inviter', 'invited', 'invite',
  'referred_by', 'referredby', 'referrer', 'referer',
  'utm', 'wt_', 'wtmc', 'pk_', 'pk_campaign', 'pk_kwd', 'pk_keyword',
  'pk_content', 'pk_medium', 'pk_source', 'pk_cid',

  // Shopify additional
  'utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term',
  'gclid', 'fbclid', 'ttclid', 'li_fat_id', 'wickedid', 'yclid',
  '_kx', '_ke', '_kn', '_kl', '_ko', '_kq', '_kr', '_ks', '_kt',
  '_ku', '_kv', '_kw', '_kx', '_ky', '_kz',

  // Twitter
  'tw_p', 'tw_w', 'tw_i', 'tw_o', 'tw_s', 'tw_c',

  // LinkedIn
  'li_fat_id', 'li_g', 'li_targetid', 'li_advertiser_id', 'li_campaign',

  // Pinterest additional
  'epik', 'epikid', 'pinterest_campaign', 'pinterest_source',

  // Snapchat additional
  'sc_source', 'sc_medium', 'sc_campaign', 'sc_content', 'sc_term',

  // Reddit additional
  'rdt_cid', 'reddit_campaign', 'reddit_source',

  // TikTok additional
  'tt_source', 'tt_medium', 'tt_campaign', 'tt_content', 'tt_term',
  'tt_ad_id', 'tt_adset_id', 'tt_campaign_id', 'tt_adgroup_id',

  // Additional UTM variants
  'utm_placement', 'utm_network', 'utm_device', 'utm_adgroup', 'utm_ad',
  'utm_matchtype', 'utm_creative', 'utm_keyword', 'utm_target',

  // Mobile app tracking
  'app_id', 'appid', 'app_name', 'appname', 'bundle_id', 'bundleid',
  'package', 'package_name', 'packagename', 'store_id', 'storeid',
]);

// ── Environment Variables that Leak Data ────────────────────
const TRACKER_ENV_VARS = new Set([
  // Analytics/tracking keys
  'GOOGLE_ANALYTICS_ID', 'GA_ID', 'GA_TRACKING_ID', 'GTAG_ID',
  'FACEBOOK_PIXEL_ID', 'FB_PIXEL_ID', 'META_PIXEL_ID',
  'SEGMENT_WRITE_KEY', 'SEGMENT_KEY',
  'AMPLITUDE_API_KEY', 'MIXPANEL_TOKEN', 'HEAP_APP_ID',
  'HOTJAR_ID', 'HOTJAR_SITE_ID', 'FULLSTORY_ORG',
  'SENTRY_DSN', 'SENTRY_KEY', 'BUGSNAG_API_KEY',
  'LOGROCKET_APP_ID', 'DATADOG_CLIENT_TOKEN', 'NEW_RELIC_LICENSE_KEY',
  'ALGOLIA_APP_ID', 'ALGOLIA_API_KEY', 'ALGOLIA_SEARCH_KEY',
  'INTERCOM_APP_ID', 'DRIFT_ID', 'CRISP_WEBSITE_ID',
  'CHATWOOT_TOKEN', 'TIDIO_PUBLIC_KEY',

  // Advertising
  'GOOGLE_ADS_ID', 'ADSENSE_ID', 'ADWORDS_ID',
  'BING_ADS_ID', 'YAHOO_ADS_ID',
  'TABOOLA_PUBLISHER_ID', 'OUTBRAIN_WIDGET_ID',
  'REVCONTENT_API_KEY', 'MGID_PUBLISHER_ID',

  // Affiliate
  'AMAZON_ASSOCIATE_TAG', 'EBAY_CAMPAIGN_ID', 'AFFILIATE_ID',

  // Social media keys
  'TWITTER_PIXEL_ID', 'LINKEDIN_PARTNER_ID', 'TIKTOK_PIXEL_ID',
  'SNAPCHAT_PIXEL_ID', 'PINTEREST_TAG_ID', 'REDDIT_PIXEL_ID',

  // Email service providers
  'MAILCHIMP_API_KEY', 'SENDGRID_API_KEY', 'MAILGUN_API_KEY',
  'POSTMARK_API_TOKEN', 'AWS_SES_ACCESS_KEY',

  // Cloud telemetry
  'AWS_CLOUDWATCH_NAMESPACE', 'AZURE_INSIGHTS_KEY', 'GCP_TRACE_ENABLED',
  'VERCEL_ANALYTICS_ID', 'NETLIFY_ANALYTICS_ID', 'RAILWAY_ENVIRONMENT',

  // Fingerprinting
  'FINGERPRINTJS_API_KEY', 'PERIMETERX_APP_ID', 'DATADOME_JS_KEY',
  'KASADA_API_KEY', 'HUMAN_SECURITY_KEY',
]);

// ── Header Patterns to Block ─────────────────────────────────
const TRACKING_HEADERS = new Set([
  'x-requested-with',
  'x-client-data',
  'x-chrome-uma-enabled',
  'x-chrome-connected',
  'x-goog-authuser',
  'x-goog-visitor-id',
  'x-youtube-client-name',
  'x-youtube-client-version',
  'x-youtube-page-cl',
  'x-youtube-page-label',
  'x-youtube-utc-offset',
  'x-youtube-ad-signals',
  'x-ga-lite-version',
  'x-facebook-conversion-tracking',
  'x-pinterest-cta-tracking',
  'x-twitter-tracking',
  'x-linkedin-track',
  'x-snapchat-track',
  'x-tiktok-track',
  'x-reddit-track',
  'x-amz-cf-id',
  'x-amz-cf-pop',
  'x-edgeconnect-midmile-rtt',
  'x-edgeconnect-origin-mex-latency',
  'x-akamai-transformed',
  'x-cache',
  'x-cache-hits',
  'x-served-by',
  'x-timer',
  'x-varnish',
  'x-fastly-request-id',
  'x-nginx-cache',
  'x-hits',
  'x-cloud-trace-context',
  'x-googletagmanager-preview',
  'x-googletagmanager-auth',
  'x-optimizely-enduserid',
  'x-amplitude-session-id',
  'x-mixpanel-distinct-id',
  'x-segment-anonymous-id',
  'x-fullstory-session',
  'x-heap-user-id',
  'x-hotjar-user-id',
  'x-logrocket-session-url',
  'x-datadog-trace-id',
  'x-newrelic-id',
  'x-sentry-trace',
  'x-bugsnag-api-key',
  'x-raygun-user',
  'x-rollbar-person',
  'x-branch-identity',
  'x-adjust-device-id',
  'x-appsflyer-id',
  'x-kochava-device-id',
  'x-firebase-instance-id',
  'x-crashlytics-installation-id',
  'x-umeng-device-id',
  'x-appsflyer-advertising-id',
  'x-adjust-gps-adid',
  'x-tenjin-advertising-id',
  'x-singular-device-id',
  'x-startapp-device-id',
  'x-adcolony-device-id',
  'x-vungle-device-id',
  'x-applovin-device-id',
  'x-ironsource-device-id',
  'x-unityads-device-id',
  'x-chartboost-device-id',
  'x-admob-device-id',
  'x-doubleclick-id',
  'x-google-dai-auth-token',
  'x-google-abuse',
  'x-goog-authuser',
  'x-goog-pageid',
  'x-goog-channel-id',
  'x-goog-encode-response-if-executable',
  'x-javascript-user-agent',
  'x-pardot-lua-url',
  'x-pardot-route',
  'x-pardot-set-cookie',
  'x-hubspot-correlation-id',
  'x-hubspot-track-payload',
  'x-marketo-tracking',
  'x-eloqua-tracking',
  'x-adobe-marketing-cloud-visitor-id',
  'x-adobe-analytics',
  'x-coreid',
  'x-campaign-code',
  'x-wp-total',
  'x-wp-totalpages',
  'x-http-method-override',
]);

// ── Known Fingerprinting Scripts/Patterns ───────────────────
const FINGERPRINT_PATTERNS = [
  // Canvas/WebGL fingerprinting
  /canvas\.toDataURL\(\)/i,
  /getImageData\s*\(/i,
  /measureText\s*\(/i,
  /getContext\s*\(\s*['"](2d|webgl|webgl2|experimental-webgl)['"]\s*\)/i,
  /getSupportedExtensions\s*\(/i,
  /getParameter\s*\(/i,
  /getShaderPrecisionFormat\s*\(/i,
  /WEBGL_debug_renderer_info/i,
  /UNMASKED_VENDOR_WEBGL/i,
  /UNMASKED_RENDERER_WEBGL/i,

  // Audio fingerprinting
  /createAnalyser\s*\(/i,
  /createOscillator\s*\(/i,
  /createDynamicsCompressor\s*\(/i,
  /destination\.stream/i,
  /AudioBuffer\.copyFromChannel/i,
  /OfflineAudioContext/i,
  /webkitOfflineAudioContext/i,

  // Font detection
  /measureText\s*\(/i,
  /offsetWidth\s*===\s*\d+/i,
  /offsetHeight\s*===\s*\d+/i,

  // WebRTC leak detection
  /RTCPeerConnection/i,
  /webkitRTCPeerConnection/i,
  /mozRTCPeerConnection/i,
  /createDataChannel/i,
  /createOffer\s*\(/i,
  /setLocalDescription/i,
  /onicecandidate/i,

  // Navigation timing
  /performance\.timing/i,
  /performance\.getEntriesByType/i,
  /performance\.now\s*\(\)/i,
  /navigationStart/i,
  /unloadEventStart/i,
  /unloadEventEnd/i,
  /redirectStart/i,
  /redirectEnd/i,
  /fetchStart/i,
  /domainLookupStart/i,
  /domainLookupEnd/i,
  /connectStart/i,
  /connectEnd/i,
  /secureConnectionStart/i,
  /requestStart/i,
  /responseStart/i,
  /responseEnd/i,
  /domLoading/i,
  /domInteractive/i,
  /domContentLoadedEventStart/i,
  /domContentLoadedEventEnd/i,
  /domComplete/i,
  /loadEventStart/i,
  /loadEventEnd/i,

  // Battery API
  /navigator\.getBattery\s*\(\)/i,
  /charging\s*:/i,
  /chargingTime\s*:/i,
  /dischargingTime\s*:/i,
  /level\s*:/i,

  // Network information
  /navigator\.connection/i,
  /connection\.effectiveType/i,
  /connection\.rtt/i,
  /connection\.downlink/i,
  /connection\.saveData/i,

  // Device sensors
  /DeviceMotionEvent/i,
  /DeviceOrientationEvent/i,
  /devicemotion/i,
  /deviceorientation/i,
  /accelerationIncludingGravity/i,
  /rotationRate/i,
  /webkitCompassHeading/i,

  // Gamepad API
  /navigator\.getGamepads/i,
  /webkitGetGamepads/i,

  // VR/AR APIs
  /navigator\.getVRDisplays/i,
  /navigator\.xr/i,
  /isSessionSupported/i,
  /requestSession/i,

  // Media devices enumeration
  /navigator\.mediaDevices\.enumerateDevices/i,
  /getUserMedia/i,
  /webkitGetUserMedia/i,
  /mozGetUserMedia/i,

  // Permissions API
  /navigator\.permissions\.query/i,
  /PermissionStatus\.onchange/i,

  // Notifications
  /Notification\.requestPermission/i,
  /new\s+Notification\s*\(/i,

  // Geolocation
  /navigator\.geolocation\.getCurrentPosition/i,
  /navigator\.geolocation\.watchPosition/i,

  // Screen properties
  /screen\.width/i,
  /screen\.height/i,
  /screen\.availWidth/i,
  /screen\.availHeight/i,
  /screen\.colorDepth/i,
  /screen\.pixelDepth/i,
  /screen\.availLeft/i,
  /screen\.availTop/i,

  // Window properties
  /window\.outerWidth/i,
  /window\.outerHeight/i,
  /window\.innerWidth/i,
  /window\.innerHeight/i,
  /window\.screenX/i,
  /window\.screenY/i,
  /window\.screenLeft/i,
  /window\.screenTop/i,
  /window\.devicePixelRatio/i,
  /window\.visualViewport/i,

  // Client rects
  /getClientRects\s*\(/i,
  /getBoundingClientRect\s*\(/i,

  // CSS styles
  /getComputedStyle/i,
  /currentStyle/i,

  // Plugins/MIME types
  /navigator\.plugins/i,
  /navigator\.mimeTypes/i,

  // Do Not Track
  /navigator\.doNotTrack/i,
  /navigator\.msDoNotTrack/i,
  /window\.doNotTrack/i,

  // Storage estimation
  /navigator\.storage\.estimate/i,
  /navigator\.storage\.persist/i,
  /navigator\.storage\.persisted/i,

  // IndexedDB
  /indexedDB\.open/i,
  /indexedDB\.deleteDatabase/i,
  /IDBFactory\.open/i,

  // Service Workers
  /navigator\.serviceWorker\.register/i,
  /navigator\.serviceWorker\.ready/i,

  // Credential Management
  /navigator\.credentials\.get/i,
  /navigator\.credentials\.create/i,
  /navigator\.credentials\.store/i,

  // Payment Request
  /PaymentRequest/i,
  /new\s+PaymentRequest/i,

  // Web Authentication
  /navigator\.credentials\.create/i,
  /PublicKeyCredential/i,
  /navigator\.credentials\.get/i,

  // Clipboard API
  /navigator\.clipboard\.readText/i,
  /navigator\.clipboard\.writeText/i,
  /navigator\.clipboard\.read/i,
  /navigator\.clipboard\.write/i,

  // Wake Lock
  /navigator\.wakeLock\.request/i,

  // Web Share
  /navigator\.share/i,
  /navigator\.canShare/i,

  // Contacts API
  /navigator\.contacts\.select/i,

  // File System Access
  /showOpenFilePicker/i,
  /showSaveFilePicker/i,
  /showDirectoryPicker/i,

  // Screen Wake Lock
  /navigator\.wakeLock/i,

  // Device Memory
  /navigator\.deviceMemory/i,

  // Hardware concurrency
  /navigator\.hardwareConcurrency/i,

  // Max touch points
  /navigator\.maxTouchPoints/i,

  // Keyboard layout
  /navigator\.keyboard/i,
  /getLayoutMap/i,

  // Pointer events
  /navigator\.maxTouchPoints/i,
  /PointerEvent/i,

  // Touch events
  /ontouchstart/i,
  /ontouchmove/i,
  /ontouchend/i,
  /TouchEvent/i,

  // Speech recognition
  /SpeechRecognition/i,
  /webkitSpeechRecognition/i,

  // Speech synthesis
  /speechSynthesis/i,
  /SpeechSynthesisUtterance/i,

  // Bluetooth
  /navigator\.bluetooth\.requestDevice/i,

  // USB
  /navigator\.usb\.requestDevice/i,

  // Serial
  /navigator\.serial\.requestPort/i,

  // HID
  /navigator\.hid\.requestDevice/i,

  // NFC
  /NDEFReader/i,

  // Ambient Light
  /AmbientLightSensor/i,

  // Accelerometer
  /Accelerometer/i,

  // Gyroscope
  /Gyroscope/i,
  /AbsoluteOrientationSensor/i,
  /RelativeOrientationSensor/i,

  // Magnetometer
  /Magnetometer/i,

  // Proximity
  /ProximitySensor/i,

  // Fingerprintjs library
  /Fingerprint2/i,
  /FingerprintJS/i,
  /@fingerprintjs/i,
  /fpjs\.io/i,
  /openfpcdn\.io/i,

  // ClientJS
  /ClientJS/i,

  // ImprintJS
  /Imprint/i,

  // PlatformJS
  /platform\.description/i,
  /platform\.layout/i,
  /platform\.manufacturer/i,
  /platform\.name/i,
  /platform\.os/i,
  /platform\.product/i,
  /platform\.version/i,

  // Bowser
  /Bowser/i,

  // UAParser
  /UAParser/i,

  // DetectRTC
  /DetectRTC/i,

  // Math random seeding
  /Math\.random\s*\(\).{0,50}new\s+Date/i,
  /Date\.now\s*\(\).{0,50}Math\.random/i,

  // Crypto getRandomValues
  /crypto\.getRandomValues/i,
  /msCrypto\.getRandomValues/i,

  // WebGL vendor/renderer extraction
  /getParameter\s*\(\s*0x9245\s*\)/i,
  /getParameter\s*\(\s*0x9246\s*\)/i,
  /37445/i,
  /37446/i,

  // Canvas winding rule
  /ctx\.isPointInPath/i,
  /context\.isPointInPath/i,

  // Canvas text
  /fillText\s*\(/i,
  /strokeText\s*\(/i,

  // Canvas arc
  /arc\s*\(/i,
  /arcTo\s*\(/i,

  // Canvas bezier
  /bezierCurveTo\s*\(/i,
  /quadraticCurveTo\s*\(/i,

  // Canvas rect
  /fillRect\s*\(/i,
  /strokeRect\s*\(/i,
  /clearRect\s*\(/i,

  // Canvas gradient
  /createLinearGradient/i,
  /createRadialGradient/i,
  /createPattern/i,

  // Canvas shadow
  /shadowBlur/i,
  /shadowColor/i,
  /shadowOffsetX/i,
  /shadowOffsetY/i,

  // Canvas composite
  /globalCompositeOperation/i,
  /globalAlpha/i,

  // WebGL extensions
  /getSupportedExtensions/i,
  /getExtension/i,

  // WebGL buffer
  /createBuffer/i,
  /bindBuffer/i,
  /bufferData/i,

  // WebGL shader
  /createShader/i,
  /shaderSource/i,
  /compileShader/i,

  // WebGL program
  /createProgram/i,
  /attachShader/i,
  /linkProgram/i,
  /useProgram/i,

  // Timing attacks
  /performance\.now\(\)/i,
  /Date\.now\(\)/i,
  /console\.time/i,
  /console\.timeEnd/i,

  // Cache probing
  /fetch\s*\(.{0,100}cache/i,
  /XMLHttpRequest.{0,50}If-Modified-Since/i,

  // HSTS fingerprinting
  /fetch\s*\(\s*['"]http:\/\//i,
  /XMLHttpRequest.{0,50}http:/i,

  // Error-based
  /onerror\s*=/i,
  /addEventListener\s*\(\s*['"]error['"]/i,
];

export class TrackerBlocker {
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.blockDomains = options.blockDomains !== false;
    this.stripParams = options.stripParams !== false;
    this.blockHeaders = options.blockHeaders !== false;
    this.sanitizeEnv = options.sanitizeEnv !== false;
    this.detectFingerprinting = options.detectFingerprinting !== false;

    this.blockedCount = 0;
    this.strippedUrls = 0;
    this.blockedHeaders = 0;
    this.clearedEnv = 0;
    this.fingerprintingAttempts = 0;

    this._dnsBlocked = [];
    this._dnsPatched = false;
    this._listeners = {};

    // LRU-bounded domain cache (max 1000 entries)
    this._domainCache = new Map();
    this._domainCacheMax = 1000;

    // Lazy-compiled regex for tracking params
    this._paramPattern = null;

    // Compiled combined regex for domain suffix matching (built once)
    this._domainSuffixRegex = null;
  }

  // Lazy-compile tracking params regex on first use
  _getParamPattern() {
    if (!this._paramPattern) {
      this._paramPattern = new RegExp(
        Array.from(TRACKING_PARAMS).map(p => `${p}=[^&]*`).join('|'),
        'gi'
      );
    }
    return this._paramPattern;
  }

  // Compiled domain suffix regex for fast batch matching
  _getDomainSuffixRegex() {
    if (!this._domainSuffixRegex) {
      // Build a regex that matches any tracker domain as a suffix
      const escaped = Array.from(TRACKER_DOMAINS).map(d => d.replace(/\./g, '\\.'));
      // Match domain ending with any tracker domain (preceded by . or start of string)
      this._domainSuffixRegex = new RegExp(`(?:^|\\.)(?:${escaped.join('|')})$`, 'i');
    }
    return this._domainSuffixRegex;
  }

  // ── Domain Blocking ─────────────────────────────────────────
  isTrackerDomain(domain) {
    if (!this.enabled || !this.blockDomains) return false;

    // Check cache
    if (this._domainCache.has(domain)) {
      return this._domainCache.get(domain);
    }

    // Normalize domain
    const normalized = domain.toLowerCase().trim();

    // Direct match (O(1) in Set)
    let isTracker = TRACKER_DOMAINS.has(normalized);

    // Fast suffix match via compiled regex if no direct match
    if (!isTracker) {
      isTracker = this._getDomainSuffixRegex().test(normalized);
    }

    // LRU eviction if cache is full
    if (this._domainCache.size >= this._domainCacheMax) {
      const firstKey = this._domainCache.keys().next().value;
      this._domainCache.delete(firstKey);
    }

    this._domainCache.set(domain, isTracker);
    if (isTracker) this.blockedCount++;
    return isTracker;
  }

  // ── URL Tracking Parameter Stripping ───────────────────────
  stripTrackingParams(url) {
    if (!this.enabled || !this.stripParams) return url;

    try {
      const urlObj = new URL(url);
      const originalSearch = urlObj.search;

      if (!originalSearch) return url;

      const params = urlObj.searchParams;
      let modified = false;

      for (const param of Array.from(params.keys())) {
        const lowerParam = param.toLowerCase();
        // Check if param is a tracking parameter
        for (const trackerParam of TRACKING_PARAMS) {
          if (lowerParam === trackerParam.toLowerCase() ||
            lowerParam.startsWith(trackerParam.toLowerCase() + '_') ||
            lowerParam.startsWith(trackerParam.toLowerCase() + '-')) {
            params.delete(param);
            modified = true;
            break;
          }
        }
      }

      if (modified) {
        this.strippedUrls++;
        // Reconstruct URL
        urlObj.search = params.toString();
        return urlObj.toString();
      }
    } catch {
      // Invalid URL, return as-is
    }

    return url;
  }

  // ── Header Sanitization ─────────────────────────────────────
  sanitizeHeaders(headers) {
    if (!this.enabled || !this.blockHeaders) return headers;

    const sanitized = { ...headers };
    let modified = false;

    for (const header of Object.keys(sanitized)) {
      const lowerHeader = header.toLowerCase();
      if (TRACKING_HEADERS.has(lowerHeader)) {
        delete sanitized[header];
        modified = true;
        this.blockedHeaders++;
      }
    }

    return modified ? sanitized : headers;
  }

  // ── Environment Variable Sanitization ───────────────────────
  sanitizeEnvironment(env) {
    if (!this.enabled || !this.sanitizeEnv) return env;

    const sanitized = { ...env };
    let modified = false;

    for (const key of Object.keys(sanitized)) {
      if (TRACKER_ENV_VARS.has(key)) {
        delete sanitized[key];
        modified = true;
        this.clearedEnv++;
      }
    }

    // Also remove any variable containing tracking keywords
    const trackingKeywords = ['TRACKING', 'ANALYTICS', 'PIXEL', 'FINGERPRINT',
      'TELEMETRY', 'MONITORING', 'SPY', 'BEACON'];

    for (const key of Object.keys(sanitized)) {
      const upperKey = key.toUpperCase();
      for (const keyword of trackingKeywords) {
        if (upperKey.includes(keyword)) {
          delete sanitized[key];
          modified = true;
          this.clearedEnv++;
          break;
        }
      }
    }

    return modified ? sanitized : env;
  }

  // ── Fingerprinting Detection ────────────────────────────────
  detectFingerprintingScript(script) {
    if (!this.enabled || !this.detectFingerprinting) return false;

    for (const pattern of FINGERPRINT_PATTERNS) {
      if (pattern.test(script)) {
        this.fingerprintingAttempts++;
        return true;
      }
    }
    return false;
  }

  // ── Request Filtering (for proxy/agent use) ─────────────────
  shouldBlockRequest(url) {
    if (!this.enabled) return false;

    try {
      const urlObj = new URL(url);
      return this.isTrackerDomain(urlObj.hostname);
    } catch {
      return false;
    }
  }

  // ── Batch URL Processing ────────────────────────────────────
  processBatch(urls) {
    return urls.map(url => ({
      original: url,
      sanitized: this.stripTrackingParams(url),
      blocked: this.shouldBlockRequest(url),
    }));
  }

  // ── Statistics ──────────────────────────────────────────────
  getStats() {
    return {
      enabled: this.enabled,
      blockedDomains: this.blockedCount,
      strippedUrls: this.strippedUrls,
      blockedHeaders: this.blockedHeaders,
      clearedEnvVars: this.clearedEnv,
      fingerprintingDetected: this.fingerprintingAttempts,
      totalTrackerDomains: TRACKER_DOMAINS.size,
      totalTrackingParams: TRACKING_PARAMS.size,
      totalTrackingHeaders: TRACKING_HEADERS.size,
      totalEnvVars: TRACKER_ENV_VARS.size,
    };
  }

  // ── Status Display ──────────────────────────────────────────
  formatStatus() {
    const stats = this.getStats();

    if (!this.enabled) {
      return chalk.yellow('  🚫 Tracker Blocker: DISABLED');
    }

    const lines = [
      chalk.green('  🚫 Tracker Blocker: ACTIVE'),
      chalk.gray(`     Domains blocked: ${stats.blockedDomains}`),
      chalk.gray(`     URLs stripped: ${stats.strippedUrls}`),
      chalk.gray(`     Headers removed: ${stats.blockedHeaders}`),
      chalk.gray(`     Env vars cleared: ${stats.clearedEnvVars}`),
      chalk.gray(`     Fingerprinting detected: ${stats.fingerprintingDetected}`),
      chalk.gray(`     Blocklist: ${stats.totalTrackerDomains.toLocaleString()}+ domains, ${stats.totalTrackingParams}+ params`),
    ];

    return lines.join('\n');
  }

  // ── Configuration ───────────────────────────────────────────
  configure(options) {
    this.enabled = options.enabled ?? this.enabled;
    this.blockDomains = options.blockDomains ?? this.blockDomains;
    this.stripParams = options.stripParams ?? this.stripParams;
    this.blockHeaders = options.blockHeaders ?? this.blockHeaders;
    this.sanitizeEnv = options.sanitizeEnv ?? this.sanitizeEnv;
    this.detectFingerprinting = options.detectFingerprinting ?? this.detectFingerprinting;
  }

  // ── Export blocklist (for external tools) ───────────────────
  exportBlocklist() {
    return {
      domains: Array.from(TRACKER_DOMAINS).sort(),
      params: Array.from(TRACKING_PARAMS).sort(),
      headers: Array.from(TRACKING_HEADERS).sort(),
      envVars: Array.from(TRACKER_ENV_VARS).sort(),
      generatedAt: new Date().toISOString(),
      totalDomains: TRACKER_DOMAINS.size,
      totalParams: TRACKING_PARAMS.size,
      totalHeaders: TRACKING_HEADERS.size,
      totalEnvVars: TRACKER_ENV_VARS.size,
    };
  }

  // ── DNS Interception ──────────────────────────────────────────
  // Monkey-patches dns.lookup in the current process so any
  // outbound DNS resolution for tracker domains is silently
  // blocked (resolves to 0.0.0.0) before it ever hits the wire.
  enableDnsInterception() {
    if (this._dnsPatched) return;
    try {
      import('dns').then((dns) => {
        const original = dns.lookup;
        const self = this;
        dns.lookup = function patchedLookup(hostname, options, callback) {
          if (typeof options === 'function') { callback = options; options = {}; }
          if (self.isTrackerDomain(hostname)) {
            self._dnsBlocked.push({ hostname, time: Date.now() });
            self.blockedCount++;
            // Return loopback so the connection silently fails
            const family = (options && options.family) || 4;
            const addr = family === 6 ? '::1' : '0.0.0.0';
            return callback(null, addr, family);
          }
          return original.call(dns, hostname, options, callback);
        };
        this._dnsPatched = true;
      }).catch(() => { });
    } catch { /* dns module may not be available */ }
  }

  getDnsBlockLog() {
    return [...(this._dnsBlocked || [])];
  }

  // ── Real-time Event Monitor ───────────────────────────────────
  // Allows subscribing to blocking events for live dashboard updates.
  on(event, handler) {
    if (!this._listeners) this._listeners = {};
    if (!this._listeners[event]) this._listeners[event] = [];
    this._listeners[event].push(handler);
  }

  _emit(event, data) {
    if (!this._listeners || !this._listeners[event]) return;
    for (const handler of this._listeners[event]) {
      try { handler(data); } catch { }
    }
  }

  // Override isTrackerDomain to emit events
  _checkAndEmit(domain) {
    const blocked = this.isTrackerDomain(domain);
    if (blocked) {
      this._emit('blocked', { type: 'domain', value: domain, time: Date.now() });
    }
    return blocked;
  }

  // ── Scan text for tracker URLs ────────────────────────────────
  // Scans arbitrary text (prompts, responses) for embedded tracker URLs.
  scanText(text) {
    const urlPattern = /https?:\/\/[^\s"'<>\])+,]+/gi;
    const found = [];
    let match;
    while ((match = urlPattern.exec(text)) !== null) {
      const url = match[0];
      try {
        const hostname = new URL(url).hostname;
        if (this.isTrackerDomain(hostname)) {
          found.push({ url, hostname, index: match.index });
        }
      } catch { }
    }
    return found;
  }

  // ── Redact tracker URLs from text ─────────────────────────────
  redactTrackerUrls(text) {
    const urlPattern = /https?:\/\/[^\s"'<>\])+,]+/gi;
    let result = text;
    const matches = this.scanText(text);
    // Replace in reverse order to preserve indices
    for (const m of matches.reverse()) {
      result = result.substring(0, m.index) + '[TRACKER_BLOCKED]' + result.substring(m.index + m.url.length);
    }
    return { text: result, blocked: matches.length };
  }

  // ── WebRTC Leak Protection ────────────────────────────────────
  // Returns env vars to set on child processes to prevent WebRTC
  // from leaking the real IP when proxy/Tor is enabled.
  getWebRtcProtectionEnv() {
    return {
      WEBRTC_IP_HANDLING_POLICY: 'disable_non_proxied_udp',
      FORCE_DISABLE_WEBRTC: '1',
    };
  }

  // ── Child Process Env Builder ─────────────────────────────────
  // Combines all protections into a single sanitized env for spawning.
  buildSafeEnv(baseEnv = process.env) {
    let env = this.sanitizeEnvironment(baseEnv);
    env = { ...env, ...this.getWebRtcProtectionEnv() };
    return env;
  }

  // ── Cookie Tracking Detection ─────────────────────────────────
  isTrackingCookie(name) {
    const trackingCookies = new Set([
      '_ga', '_gid', '_gat', '_gac', '__utma', '__utmb', '__utmc', '__utmz', '__utmv',
      '_fbp', '_fbc', 'fr', 'datr', 'sb', 'wd', 'xs',
      '_pin_unauth', '_pinterest_sess', '_pinterest_ct_ua',
      'IDE', 'DSID', 'FLC', 'AID', 'TAID', '__gads', 'test_cookie',
      '_gcl_au', '_gcl_aw', 'NID', '1P_JAR', 'CONSENT', 'DV', 'S',
      'li_sugr', 'bcookie', 'bscookie', 'lang', 'lidc', 'UserMatchHistory',
      'MUID', '_uetsid', '_uetvid', 'ANONCHK', 'MR', 'SM',
      '_tt_enable_cookie', '_ttp', 'tt_webid', 'tt_webid_v2',
      'mp_mixpanel', 'amplitude_id', 'ajs_user_id', 'ajs_anonymous_id',
      '_hjid', '_hjSessionUser', '_hjSession', '_hjAbsoluteSessionInProgress',
    ]);
    return trackingCookies.has(name) ||
      name.startsWith('_ga_') || name.startsWith('_gac_') ||
      name.startsWith('_gcl_') || name.startsWith('_hj') ||
      name.startsWith('mp_') || name.startsWith('ajs_');
  }

  // ── Enhanced Status with Live Stats ───────────────────────────
  formatDetailedStatus() {
    const stats = this.getStats();

    if (!this.enabled) {
      return chalk.yellow('  🚫 Tracker Blocker: DISABLED');
    }

    const dnsBlocked = (this._dnsBlocked || []).length;
    const lines = [
      chalk.green.bold('  🚫 TRACKER BLOCKER: ACTIVE'),
      '',
      chalk.white('     Blocklist Coverage:'),
      chalk.gray(`       Domains:       ${stats.totalTrackerDomains.toLocaleString()}+`),
      chalk.gray(`       URL Params:    ${stats.totalTrackingParams}+`),
      chalk.gray(`       Headers:       ${stats.totalTrackingHeaders}`),
      chalk.gray(`       Env Vars:      ${stats.totalEnvVars}`),
      '',
      chalk.white('     Session Activity:'),
      chalk.gray(`       Domains blocked:         ${stats.blockedDomains}`),
      chalk.gray(`       URLs stripped:            ${stats.strippedUrls}`),
      chalk.gray(`       Headers removed:          ${stats.blockedHeaders}`),
      chalk.gray(`       Env vars cleared:         ${stats.clearedEnvVars}`),
      chalk.gray(`       Fingerprinting caught:    ${stats.fingerprintingDetected}`),
      chalk.gray(`       DNS queries blocked:      ${dnsBlocked}`),
      '',
      chalk.white('     Protection Layers:'),
      chalk.gray(`       Domain blocking:          ${this.blockDomains ? chalk.green('ON') : chalk.red('OFF')}`),
      chalk.gray(`       URL param stripping:      ${this.stripParams ? chalk.green('ON') : chalk.red('OFF')}`),
      chalk.gray(`       Header sanitization:      ${this.blockHeaders ? chalk.green('ON') : chalk.red('OFF')}`),
      chalk.gray(`       Env var cleaning:         ${this.sanitizeEnv ? chalk.green('ON') : chalk.red('OFF')}`),
      chalk.gray(`       Fingerprint detection:    ${this.detectFingerprinting ? chalk.green('ON') : chalk.red('OFF')}`),
      chalk.gray(`       DNS interception:         ${this._dnsPatched ? chalk.green('ON') : chalk.yellow('AVAILABLE')}`),
      chalk.gray(`       WebRTC leak protection:   ${chalk.green('ON')}`),
      chalk.gray(`       Cookie tracking detect:   ${chalk.green('ON')}`),
    ];

    return lines.join('\n');
  }

  // ── Reset ──────────────────────────────────────────────────
  resetStats() {
    this.blockedCount = 0;
    this.strippedUrls = 0;
    this.blockedHeaders = 0;
    this.clearedEnv = 0;
    this.fingerprintingAttempts = 0;
    this._domainCache.clear();
    this._dnsBlocked = [];
  }
}

// Export the sets for advanced use
export { TRACKER_DOMAINS, TRACKING_PARAMS, TRACKING_HEADERS, TRACKER_ENV_VARS, FINGERPRINT_PATTERNS };
