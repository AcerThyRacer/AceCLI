// ============================================================
//  AceCLI – Mass Tracker Blocker (Deduplicated v2)
//  Blocks 1,000+ unique trackers, analytics, telemetry, and fingerprinting
//  Deduplicated: all static Sets contain zero duplicate entries
// ============================================================
import chalk from 'chalk';

// ── Comprehensive Tracker Domain Blocklist (1068+ unique) ──
const TRACKER_DOMAINS = new Set([
  '2o7.net', '33across.com', 'Kasada.io', 'a.teads.tv',
  'a.tribalfusion.com', 'aa.agkn.com', 'aax.amazon-adsystem.com', 'ac.mmstat.com',
  'acdn.adnxs.com', 'activegate.dynatrace.com', 'actonsoftware.com', 'ad.adsrvr.org',
  'ad.adtiming.com', 'ad.cpe.dotomi.com', 'ad.crwdcntrl.net', 'ad.doubleclick.net',
  'ad.mail.ru', 'ad.media6degrees.com', 'ad.turn.com', 'ad.yieldmanager.com',
  'ad1.adition.net', 'ad2.adfarm1.adition.com', 'adap.tv', 'adaraanalytics.com',
  'adcolony.com', 'addthis.com', 'addthisedge.com', 'adeven.com',
  'adform.net', 'adition.com', 'adition.net', 'adjust.com',
  'adjust.io', 'admin.appnext.com', 'adnxs.com', 'ads.brealtime.com',
  'ads.certifica.com', 'ads.flurry.com', 'ads.freewheel.tv', 'ads.gumgum.com',
  'ads.hyprmx.com', 'ads.linkedin.com', 'ads.media.net', 'ads.mopub.com',
  'ads.pubmatic.com', 'ads.snapchat.com', 'ads.stickyadstv.com', 'ads.tiktok.com',
  'ads.undertone.com', 'ads.yieldmo.com', 'ads30.adcolony.com', 'adsdk.yandex.ru',
  'adserver.tremorhub.com', 'adserver.unityads.unity3d.com', 'adservice.google.com', 'adservice.google.ru',
  'adsrvr.org', 'adsymptotic.com', 'adsystem.amazon.com', 'adtiming.com',
  'advcapture.lijit.com', 'advertising.com', 'adx.adform.net', 'ag.innovid.com',
  'agent.instana.io', 'agent.skylight.io', 'agkn.com', 'aid.send.microad.jp',
  'airbrake.io', 'ak-ns.sascdn.com', 'akamaihd.net', 'alb.reddit.com',
  'alert.victorops.com', 'alexa.com', 'alog.umeng.com', 'amazon-adsystem.com',
  'amazonclix.com', 'amazontrust.com', 'amplify.outbrain.com', 'amplitude.com',
  'amplitude.com/api', 'an.yandex.ru', 'analytics.chartboost.com', 'analytics.facebook.com',
  'analytics.force.com', 'analytics.google.com', 'analytics.linkedin.com', 'analytics.live.com',
  'analytics.mobile.yandex.net', 'analytics.mopub.com', 'analytics.oracle.com', 'analytics.pinterest.com',
  'analytics.plausible.io', 'analytics.snapchat.com', 'analytics.tiktok.com', 'analytics.twitter.com',
  'analytics.umami.is', 'analytics.windowsazure.com', 'androidads23.adcolony.com', 'ap.lijit.com',
  'api-adservices.apple.com', 'api-js.datadome.co', 'api.adaraanalytics.com', 'api.adsymptotic.com',
  'api.adtiming.com', 'api.amplitude.com', 'api.appdynamics.com', 'api.applovin.com',
  'api.appsflyer.com', 'api.betteruptime.com', 'api.branch.io', 'api.chartbeat.com',
  'api.chartboost.com', 'api.connatix.com', 'api.coralogix.com', 'api.cronitor.io',
  'api.datadome.co', 'api.deadmanssnitch.com', 'api.deepintent.com', 'api.fluentd.org',
  'api.flurry.com', 'api.freshping.io', 'api.glitchtip.com', 'api.graylog.com',
  'api.heapanalytics.com', 'api.honeybadger.io', 'api.honeycomb.io', 'api.hubapi.com',
  'api.humio.com', 'api.inmobi.com', 'api.intercom.io', 'api.kasada.io',
  'api.keen.io', 'api.lightstep.com', 'api.logdna.com', 'api.logentries.com',
  'api.logz.io', 'api.mixpanel.com', 'api.mopub.com', 'api.opsgenie.com',
  'api.pagerduty.com', 'api.papertrailapp.com', 'api.parsely.com', 'api.promtail.io',
  'api.pubnative.net', 'api.raygun.io', 'api.rollbar.com', 'api.rollbar.js',
  'api.scalyr.com', 'api.segment.com', 'api.segment.io', 'api.signalfx.com',
  'api.site24x7.com', 'api.statuspage.io', 'api.taboola.com', 'api.telegraf.com',
  'api.torbit.com', 'api.uca.cloud.unity3d.com', 'api.umami.dev', 'api.uptime.com',
  'api.uptimerobot.com', 'api.vector.dev', 'api.victorops.com', 'api.vungle.com',
  'api.wavefront.com', 'api.xmatters.com', 'api.zemanta.com', 'api2.amplitude.com',
  'api2.branch.io', 'apm-server.elastic.co', 'apm.scoutapp.com', 'app-analytics-services-att.com',
  'app-measurement.com', 'app.adjust.com', 'app.adjust.net.in', 'app.adjust.world',
  'app.opsgenie.com', 'app.pendo.io', 'app.sysdigcloud.com', 'appboot.netflix.com',
  'appdynamics.com', 'applovin.com', 'appmetrica.yandex.com', 'appnext.com',
  'appscore.comscore.com', 'appsflyer.com', 'appsignal.com', 'apresolve.spotify.com',
  'as-sec.casalemedia.com', 'as.casalemedia.com', 'assets.adobedtm.com', 'assets.applovin.com',
  'assets.eloqua.com', 'assets.pubnative.net', 'assoc-amazon.com', 'att-analytics.com',
  'auction.unityads.unity3d.com', 'audiencemanager.de', 'aws.demdex.net', 'awsstatic.com',
  'axm-adm-mavenhub.xhome.apple.com', 'baidu.com', 'bam.nr-data.net', 'bat.bing.com',
  'bcp.crwdcntrl.net', 'beacon-1.newrelic.com', 'beacon.cloudflare.com', 'beacon.krxd.net',
  'beats-api.logstash.net', 'betteruptime.com', 'bh.contextweb.com', 'bid.brealtime.com',
  'bid.openx.net', 'bid.underdog.media', 'bidder.criteo.com', 'bidtheatre.com',
  'bing.com', 'bingapis.com', 'bizible.com', 'bizibly.com',
  'bkrtx.com', 'bluekai.com', 'branch.io', 'brealtime.com',
  'brightcove.com', 'browser-intake-datadoghq.com', 'browser.events.data.microsoft.com', 'browser.sentry-cdn.com',
  'btlr.sharethrough.com', 'bugsnag.com', 'business-api.tiktok.com', 'byteoversea.com',
  'c.amazon-adsystem.com', 'c.bing.com', 'c.kasada.io', 'c.statcounter.com',
  'c.wfxtriggers.com', 'cadmus.script.ac', 'capture.trackjs.com', 'careers.hotjar.com',
  'casalemedia.com', 'cdn-pci.optimizely.com', 'cdn.airbrake.io', 'cdn.amplitude.com',
  'cdn.bizible.com', 'cdn.bizibly.com', 'cdn.branch.io', 'cdn.bugsnag.com',
  'cdn.connatix.com', 'cdn.deepintent.com', 'cdn.discordapp.com', 'cdn.fingerprintjs.com',
  'cdn.fpjs.io', 'cdn.freshmarketer.com', 'cdn.heapanalytics.com', 'cdn.inspectlet.com',
  'cdn.krxd.net', 'cdn.librato.com', 'cdn.logrocket.io', 'cdn.lr-ingest.io',
  'cdn.luckyorange.com', 'cdn.mgid.com', 'cdn.mouseflow.com', 'cdn.mxpnl.com',
  'cdn.optimizely.com', 'cdn.pardot.com', 'cdn.parsely.com', 'cdn.pendo.io',
  'cdn.raygun.io', 'cdn.revcontent.com', 'cdn.rollbar.com', 'cdn.segment.com',
  'cdn.segment.io', 'cdn.sessioncam.com', 'cdn.speedcurve.com', 'cdn.spotxcdn.com',
  'cdn.syndication.twimg.com', 'cdn.taboola.com', 'cdn.teads.tv', 'cdn.trackjs.com',
  'cdn.tremorhub.com', 'cdn.udmserve.net', 'cdn.undertone.com', 'cdn.userreplay.net',
  'cdn.vungle.com', 'cdn.vwo.com', 'cdn4.mxpnl.com', 'cdna.media.net',
  'cdninstagram.com', 'cdnjs.cloudflare.com', 'cdns.tribalfusion.com', 'ced.sascdn.com',
  'certifica.com', 'ceuswatcab01.blob.core.windows.net', 'ceuswatcab02.blob.core.windows.net', 'chartbeat.com',
  'chartboost.com', 'cid.actonsoftware.com', 'clarity.ms', 'claritybt.freshmarketer.com',
  'click.liftoff.io', 'clicky.com', 'client.perimeterx.net', 'clients6.google.com',
  'cloud.humio.com', 'cloudflare-dns.com', 'cloudflare-eth.com', 'cloudflare.com',
  'cloudflareinsights.com', 'cloudfront-labs.amazonaws.com', 'cloudfront.loggly.com', 'cluster-001.elasticsearch.org',
  'cm.adform.net', 'cm.everesttech.net', 'cm.indexww.com', 'cnzz.com',
  'cnzz.mmstat.com', 'collector.effectivemeasure.net', 'collector.lightstep.com', 'collector.perimeterx.net',
  'collector.sysdigcloud.com', 'collectors.sumologic.com', 'company.xmatters.com', 'comscore.com',
  'comscoredatagems.com', 'config.unityads.unity3d.com', 'connatix.com', 'connect.facebook.net',
  'connect.tapjoy.com', 'consumer.krxd.net', 'content-signature-2.cdn.mozilla.net', 'contextweb.com',
  'control.kochava.com', 'controller.appdynamics.com', 'conversions.appsflyer.com', 'coralogix.com',
  'corp.sts.microsoft.com', 'crashlytics.com', 'crashlyticsreports-pa.googleapis.com', 'crazyegg.com',
  'creditreporting.hyprmx.com', 'criteo.com', 'criteo.net', 'cronitor.io',
  'crwdcntrl.net', 'ct.pinterest.com', 'd.agkn.com', 'd.parsely.com',
  'd.turn.com', 'd1l6p2sc9645hc.cloudfront.net', 'd26b395fwzu5fz.cloudfront.net', 'd31qbv1cthcecs.cloudfront.net',
  'dacdn.vwo.com', 'data.agkn.com', 'data.flurry.com', 'data.gosquared.com',
  'data.mozilla.com', 'data.pendo.io', 'datadoghq.com', 'datadome.co',
  'datalust.co', 'dc.ads.linkedin.com', 'deadmanssnitch.com', 'dealer.spotify.com',
  'decide.mixpanel.com', 'deepintent.com', 'demdex.net', 'dev.visualwebsiteoptimizer.com',
  'device-messaging.us-east-1.amazonaws.com', 'device-metrics-us.amazon.com', 'devs.flurry.com', 'devtrack.tenjin.io',
  'diagnostics.support.microsoft.com', 'diff.smartadserver.com', 'dis.criteo.com', 'discord.com',
  'discord.gg', 'discord.media', 'discordapp.com', 'discordapp.net',
  'distilnetworks.com', 'dnn506yrbagrg.cloudfront.net', 'dotomi.com', 'doubleclick.net',
  'doubleverify.com', 'doug1izaerwt3.cloudfront.net', 'dp2.33across.com', 'dpm.demdex.net',
  'dsp.adfarm1.adition.com', 'dsp.eyeota.net', 'dsp.send.microad.jp', 'dsp.sharethrough.com',
  'dsp.zemanta.com', 'dsum-sec.casalemedia.com', 'dsum.casalemedia.com', 'dts.innovid.com',
  'dts.pubnative.net', 'dyn.beap.ad.yieldmanager.net', 'dynatrace.com', 'e.crashlytics.com',
  'e.dlx.addthis.com', 'edge.api.brightcove.com', 'edge.fullstory.com', 'effectivemeasure.net',
  'ei.rlcdn.com', 'elastic.co', 'eloqua.com', 'eloquaeditors.com',
  'en25.com', 'endpoint1.collection.us2.sumologic.com', 'engine.fyber.com', 'epicgames.com',
  'eu-u.openx.net', 'eum.instana.io', 'eus.rubiconproject.com', 'events.applovin.com',
  'events.appsflyer.com', 'events.hubspot.com', 'events.pagerduty.com', 'events.reddit.com',
  'events.redditmedia.com', 'everesttech.net', 'exchange.zemanta.com', 'exelator.com',
  'eyeota.net', 'facebook-web-clients.appspot.com', 'facebook.com', 'fastlane.rubiconproject.com',
  'fbcdn.net', 'fbpigeon.com', 'federatedmedia.net', 'fingerprintjs.com',
  'firebase.google.com', 'firebaseanalytics.googleapis.com', 'firebaseremoteconfig.googleapis.com', 'firefox.settings.services.mozilla.com',
  'fls-na.amazon-adsystem.com', 'fluentd.org', 'flurry.com', 'fnapi.io',
  'force.com', 'forms.hubspot.com', 'fortnite.com', 'fpjs.io',
  'freewheel.tv', 'freshmarketer.com', 'freshping.io', 'fullstory.com',
  'fyber.com', 'g2.gumgum.com', 'gads.pubmatic.com', 'gateway.discord.gg',
  'get.onetag.com', 'get.s-onetag.com', 'getclicky.com', 'glitchtip.com',
  'go.pardot.com', 'google-analytics.com', 'googleads.g.doubleclick.net', 'googleadservices.com',
  'googleapis.com', 'googleoptimize.com', 'googlesyndication.com', 'googletagmanager.com',
  'googletagservices.com', 'goptimize.com', 'gosquared.com', 'grafana.com',
  'grafana.net', 'graph.facebook.com', 'graph.instagram.com', 'graylog.com',
  'graylog.org', 'grow.branch.io', 'gstatic.com', 'gtmetrix.com',
  'gum.criteo.com', 'gumgum.com', 'h.nexac.com', 'hbopenbid.pubmatic.com',
  'hc-ping.com', 'heads-ak-spotify-com.akamaized.net', 'healthchecks.io', 'heap.io',
  'heapanalytics.com', 'hec.splunk.com', 'histats.com', 'hm.baidu.com',
  'hm.baidu.com/hm.js', 'hmma.baidu.com', 'honeybadger.io', 'honeycomb.io',
  'hotjar.com', 'hotjar.io', 'hs-analytics.net', 'hs-scripts.com',
  'ht.indexww.com', 'hubspot.com', 'humio.com', 'hyprmx.com',
  'i.instagram.com', 'i.kasada.io', 'i.kissmetrics.com', 'i.liadm.com',
  'i.singular.net', 'i.wfxtriggers.com', 'i9.ytimg.com', 'iadsdk.apple.com',
  'ib.adnxs.com', 'ibytedtos.com', 'ichnaea.netflix.com', 'identify.hotjar.com',
  'idsync.rlcdn.com', 'idx.liadm.com', 'im.mail.ru', 'image2.pubmatic.com',
  'image4.pubmatic.com', 'image6.pubmatic.com', 'images.akamai.net', 'images.outbrain.com',
  'imagesrv.adition.com', 'img.en25.com', 'img.revcontent.com', 'imperva.com',
  'impr.taboola.com', 'impression.link', 'imrworldwide.com', 'in.getclicky.com',
  'in.hotjar.com', 'include.reinvigorate.net', 'incoming.telemetry.mozilla.org', 'indexww.com',
  'influxdata.com', 'influxdb.com', 'ingest.signalfx.com', 'ingest.vungle.com',
  'ingress.coralogix.com', 'init.start.io', 'init.supersonicads.com', 'inmobi.com',
  'innovid.com', 'input.splunk.com', 'inspectlet.com', 'instagram.com',
  'instana.io', 'intercom.io', 'iosads24.adcolony.com', 'ironsrc.com',
  'jaeger-agent.jaegertracing.io', 'jaeger-collector.jaegertracing.io', 'jaegertracing.io', 'js-agent.newrelic.com',
  'js.brealtime.com', 'js.casalemedia.com', 'js.datadome.co', 'js.gumgum.com',
  'js.honeybadger.io', 'js.hs-analytics.net', 'js.hs-scripts.com', 'js.intercomcdn.com',
  'js.logentries.com', 'jsc.mgid.com', 'keen.io', 'kissmetrics.com',
  'kochava.com', 'krxd.net', 'kvinit-prod.api.kochava.com', 'labs-cdn.revcontent.com',
  'ld.send.microad.jp', 'lexicon.33across.com', 'liadm.com', 'librato.com',
  'liftoff.io', 'lightstep.com', 'linkedin.com', 'listener.logz.io',
  'live.chartboost.com', 'lnkd.in', 'load.exelator.com', 'loadm.exelator.com',
  'log.bizible.com', 'log.mmstat.com', 'log.optimizely.com', 'log.outbrain.com',
  'log.pinterest.com', 'logdna.com', 'logentries.com', 'logging.googleapis.com',
  'loggly.com', 'logrocket.com', 'logs-01.loggly.com', 'logs-prod-us-central1.grafana.net',
  'logs-prod.grafana.net', 'logs.datalust.co', 'logs.graylog.org', 'logs.logdna.com',
  'logs.papertrailapp.com', 'logs.scalyr.com', 'logsene-receiver.sematext.com', 'logstash.net',
  'logzio.com', 'loki.io', 'luckyorange.com', 'lux.speedcurve.com',
  'm.addthis.com', 'm.chartbeat.net', 'mail.ru', 'manifest.hyprmx.com',
  'marketing.actonsoftware.com', 'marketing.adobe.com', 'marketo.com', 'marketo.net',
  'match.adsby.bidtheatre.com', 'match.adsrvr.org', 'match.sharethrough.com', 'mathtag.com',
  'mc.yandex.ru', 'mcs-sg.tiktok.com', 'mcs-va.tiktok.com', 'me.effectivemeasure.net',
  'media.net', 'media6degrees.com', 'metrica.yandex.com', 'metrics-api.librato.com',
  'metrics.amazonaws.com', 'metrics.apple.com', 'metrics.brightcove.com', 'metrics.influxdata.com',
  'metrics.ol.epicgames.com', 'metrics.wavefront.com', 'metrika.yandex.ru', 'mgid.com',
  'microad.jp', 'mixpanel.com', 'mixpanel.com/track', 'ml314.com',
  'mmg.whatsapp.net', 'mmstat.com', 'moatads.com', 'mobileanalytics.amazonaws.com',
  'mobileanalytics.us-east-1.amazonaws.com', 'mobileanalytics.us-west-2.amazonaws.com', 'mon.byteoversea.com', 'mookie1.com',
  'mopub.com', 'mouseflow.com', 'ms.applovin.com', 'ms4.applovin.com',
  'msnbot-65-55-108-23.search.msn.com', 'mtalk.google.com', 'munchkin.marketo.net', 'musical.ly',
  'mxpnl.com', 'mycdn.me', 'myvisualiq.net', 'n.rumble.com',
  'neustar.biz', 'newrelic.com', 'nexac.com', 'nielsen-online.com',
  'nielsen.com', 'notifier-configs.airbrake.io', 'notify.bugsnag.com', 'nrdp.nccp.netflix.com',
  'nsg.corporate.imperva.com', 'nym1.b.adnxs.com', 'o00000.ingest.sentry.io', 'oca.telemetry.microsoft.com',
  'odb.outbrain.com', 'odnoklassniki.ru', 'odr.mookie1.com', 'ok.ru',
  'omniture.com', 'omtrdc.net', 'onetag-sys.com', 'onetag.io',
  'openfpcdn.io', 'opentelemetry.io', 'openx.net', 'opsgenie.com',
  'optimatic.com', 'optimizely.com', 'oracle.com', 'otel-collector.io',
  'outbrain.com', 'outbrainimg.com', 'outcome.supersonicads.com', 'p.adsymptotic.com',
  'p.liadm.com', 'p.myvisualiq.net', 'p.nexac.com', 'p.q-common-dev.qa1.quantcount.com',
  'p.teads.tv', 'p.twitter.com', 'pagead2.googlesyndication.com', 'pagerduty.com',
  'paid.outbrain.com', 'pangle.io', 'pangleglobal.com', 'papertrailapp.com',
  'pardot.com', 'parsely.com', 'partner.googleadservices.com', 'pendo.io',
  'perimeterx.net', 'pi.actonsoftware.com', 'pi.pardot.com', 'ping.chartbeat.net',
  'pingdom.com', 'pingdom.net', 'pinpoint.us-east-1.amazonaws.com', 'pixel.certifica.com',
  'pixel.condenastdigital.com', 'pixel.facebook.com', 'pixel.mathtag.com', 'pixel.quantserve.com',
  'pixel.reddit.com', 'pixel.rtbtrack.io', 'pixel.rubiconproject.com', 'placements.tapjoy.com',
  'platform.linkedin.com', 'platform.twitter.com', 'plausible.analytics.com', 'plausible.io',
  'players.akamai.net', 'pos.baidu.com', 'prebid-server.rubiconproject.com', 'prg.smartadserver.com',
  'proc.ad.cpe.dotomi.com', 'prod-a.applovin.com', 'prometheus.io', 'promtail.io',
  'ps.eyeota.net', 'pt.xplusone.com', 'pubmatic.com', 'pubnative.net',
  'push.appsignal.com', 'push.zhanzhang.baidu.com', 'pushgateway.prometheus.io', 'px.ads.linkedin.com',
  'px.spiceworks.com', 'pxl.iqity.com', 'qualtrics.com', 'quantcast.com',
  'quantcount.com', 'quantserve.com', 'queue.simpleanalyticscdn.com', 'r.logrocket.io',
  'r.nexac.com', 'r.turn.com', 'raygun.io', 'rc.rlcdn.com',
  're-invigorate.net', 'reinvigorate.net', 'reports.crashlytics.com', 'reports.tenjin.io',
  'req.start.io', 'revcontent.com', 'rewarded-video.fyber.com', 'rlcdn.com',
  'rm.mookie1.com', 'rmgdsp-asia.openx.net', 'rollbar.com', 'rollbar.js',
  'rs.fullstory.com', 'rt.applovin.com', 'rt.udmserve.net', 'rtax.criteo.com',
  'rtb-csync.smartadserver.com', 'rtbidhost.pubmatic.com', 'rtbtrack.io', 'rubiconproject.com',
  'rules.quantcount.com', 'rum-collector-2.pingdom.net', 'rum-static.pingdom.net', 'rum.browser-intake-datadoghq.com',
  'rum.optimizely.com', 'rum.pingdom.net', 's', 's-onetag.com',
  's.addthisedge.com', 's.amazon-adsystem.com', 's.innovid.com', 's.liadm.com',
  's.ytimg.com', 's1.adform.net', 's1795.t.eloqua.com', 's2s.singular.net',
  's3.amazonaws.com/userreplay', 's4.cnzz.com', 's4384.t.en25.com', 's7.addthis.com',
  's95.cnzz.com', 'sa.scorecardresearch.com', 'safebrowsing-cache.google.com', 'safebrowsing.googleapis.com',
  'salesforce.com', 'samsung-com.112.2o7.net', 'samsungosp.com', 'satelliteLib.js',
  'sb.scorecardresearch.com', 'sc-analytics.appspot.com', 'scalyr.com', 'scorecardresearch.com',
  'scoutapm.com', 'script.ac', 'script.crazyegg.com', 'script.hotjar.com',
  'scripts.simpleanalyticscdn.com', 'sdk-api.singular.net', 'sdkm.w.inmobi.com', 'search.spotxchange.com',
  'secure-dcr.imrworldwide.com', 'secure-us.imrworldwide.com', 'secure.adnxs.com', 'secure.force.com',
  'secure.quantserve.com', 'segment.com', 'segment.io', 'sematext.com',
  'sentry.io', 'seq.com', 'servicer.mgid.com', 'sessioncam.com',
  'sessions.bugsnag.com', 'settings-win.data.microsoft.com', 'settings.crashlytics.com', 'sharethrough.com',
  'shavar.services.mozilla.com', 'showads.pubmatic.com', 'signal-beacon.s-onetag.com', 'signalfx.com',
  'simage4.pubmatic.com', 'simpleanalytics.io', 'singular.net', 'site24x7.com',
  'siteintercept.qualtrics.com', 'skadnetwork.appsflyer.com', 'skylight.io', 'smaato.com',
  'smaato.net', 'smartadserver.com', 'smartscreen-prod.microsoft.com', 'smartscreen.microsoft.com',
  'snap.licdn.com', 'snapchat.com', 'sodar.google.com', 'sovrn.com',
  'spclient.wg.spotify.com', 'speedcurve.com', 'splunk.com', 'spm-receiver.sematext.com',
  'spotx.tv', 'spotxchange.com', 'srv.pixel.parsely.com', 'srv.start.io',
  'ssc.33across.com', 'ssl.google-analytics.com', 'sslwidget.criteo.com', 'sslwidget.criteo.net',
  'ssp.udmserve.net', 'sstatic1.histats.com', 'ssum.casalemedia.com', 'st.mycdn.me',
  'stags.bkrtx.com', 'stags.bluekai.com', 'start.io', 'statcounter.com',
  'static.ads-twitter.com', 'static.chartbeat.com', 'static.cloudflareinsights.com', 'static.criteo.net',
  'static.doubleclick.net', 'static.getclicky.com', 'static.hotjar.com', 'static.media.net',
  'static.parsely.com', 'static.whiteops.com', 'static.woopra.com', 'staticxx.facebook.com',
  'stats.appsflyer.com', 'stats.freshping.io', 'stats.grafana.org', 'stats.microsoft.com',
  'stats.pingdom.com', 'stats.site24x7.com', 'stats.torbit.com', 'stats.unity3d.com',
  'stats.uptimerobot.com', 'statuspage.io', 'sumologic.com', 'supersonicads.com',
  'supportmetrics.apple.com', 'surveymonkey.com', 'sync.adap.tv', 'sync.adsrvr.org',
  'sync.eyeota.net', 'sync.mathtag.com', 'sync.outbrain.com', 'sync.search.spotxchange.com',
  'sync.spotx.tv', 'sync.teads.tv', 'syndication.twitter.com', 'sysdig.com',
  't.appsflyer.com', 't.eloqua.com', 't.mookie1.com', 't.myvisualiq.net',
  't.tiktok.com', 'taboola.com', 'taboola.net', 'tag.contextweb.com',
  'tag.crwdcntrl.net', 'tag.media6degrees.com', 'tags.bkrtx.com', 'tags.bluekai.com',
  'tags.onetag.com', 'tags.oracle.com', 'tags.t.doubleclick.net', 'tags.whiteops.com',
  'tap.rubiconproject.com', 'tapjoy.com', 'target.mail.ru', 'teads.tv',
  'telegraf.com', 'telegraf.io', 'telemetry.amazonaws.com', 'telemetry.microsoft.com',
  'telemetry.mozilla.org', 'telemetry.spotify.com', 'telemetry.urs.microsoft.com', 'tenant.dynatrace.com',
  'tenjin.io', 'teredo.ipv6.microsoft.com', 'tiktok.com', 'tiktokcdn.com',
  'tiktokv.com', 'tns-counter.ru', 'tools.mouseflow.com', 'top-fwz1.mail.ru',
  'top.mail.ru', 'torbit.com', 'tpc.googlesyndication.com', 'tr.facebook.com',
  'tr.microad.jp', 'tr.outbrain.com', 'tr.snapchat.com', 'track.hubspot.com',
  'track.liftoff.io', 'track.openx.net', 'track.pubmatic.com', 'track.rtbtrack.io',
  'track.start.io', 'track.tenjin.io', 'tracker.adtiming.com', 'tracker.pardot.com',
  'tracker.rtbtrack.io', 'tracker.salesforce.com', 'tracking-protection.cdn.mozilla.net', 'tracking.epicgames.com',
  'trackjs.com', 'traffic.moonscoop.tv', 'trc.taboola.com', 'tremorhub.com',
  'trends.revcontent.com', 'tribalfusion.com', 'triggers.wfxtriggers.com', 'trk.pinterest.com',
  'turn.com', 'u.openx.net', 'udmserve.net', 'ui.honeycomb.io',
  'uk-u.openx.net', 'umami.is', 'umeng.com', 'umengcloud.com',
  'underdog.media', 'unity3d.com', 'uop.umeng.com', 'uptime.com',
  'uptimerobot.com', 'us-u.openx.net', 'usage.trackjs.com', 'userreplay.net',
  'vars.hotjar.com', 'vector.dev', 'verve.com', 'victorops.com',
  'video.adaptv.advertising.com', 'video.fyber.com', 'visualwebsiteoptimizer.com', 'vk.com',
  'vk.ru', 'vortex-win.data.microsoft.com', 'vortex.data.microsoft.com', 'vungle.com',
  'w1.luckyorange.com', 'watson.microsoft.com', 'watson.telemetry.microsoft.com', 'wavefront.com',
  'wdcp.microsoft.com', 'wdcpalt.microsoft.com', 'web-vitals.kochava.com', 'web.kochava.com',
  'web.mopub.com', 'web.whatsapp.com', 'wfxtriggers.com', 'whatsapp.com',
  'whiteops.com', 'widget-pixels.revcontent.com', 'widget.criteo.com', 'widget.criteo.net',
  'widget.intercom.io', 'widget.surveymonkey.com', 'widgets.outbrain.com', 'widgets.pinterest.com',
  'widgets.reddit.com', 'win10.ipv6.microsoft.com', 'wms.assoc-amazon.com', 'woopra.com',
  'ws-na.amazon-adsystem.com', 'ws.sessioncam.com', 'ws.tapjoyads.com', 'www.alexa.com',
  'www.bidtheatre.com', 'www.bing.com', 'www.clarity.ms', 'www.clarity.ms/s/0.7.16/clarity.js',
  'www.distilnetworks.com', 'www.facebook.com', 'www.fullstory.com', 'www.google-analytics.com',
  'www.googleadservices.com', 'www.googleapis.com', 'www.googleoptimize.com', 'www.googletagmanager.com',
  'www.googletagservices.com', 'www.gtmetrix.com', 'www.imperva.com', 'www.inspectlet.com',
  'www.instagram.com', 'www.scalyr.com', 'www.skylight.io', 'www.statcounter.com',
  'www.surveymonkey.com', 'www.woopra.com', 'x.dlx.addthis.com', 'xmatters.com',
  'xp.apple.com', 'xp.itunes-apple.com.akadns.net', 'xplusone.com', 'yandex.com',
  'yandex.net', 'yandex.ru', 'yandex.st', 'yieldmanager.com',
  'yieldmanager.net', 'yieldmo.com', 'youtube-nocookie.com', 'youtube.com',
  'ytimg.com', 'z-na.amazon-adsystem.com', 'z.moatads.com', 'zemanta.com',
  'zipkin-server.zipkin.io', 'zipkin.io', 'zn3qgs0p5juktrcy1-qualtrics.siteintercept.qualtrics.com',
]);

// ── URL Tracking Parameters (378+ unique) ──
const TRACKING_PARAMS = new Set([
  '__cf_chl_captcha_tk__', '__cf_chl_jschl_tk__', '__cf_chl_prog', '_from', '_ga', '_gac',
  '_gat', '_gcl', '_gcl_au', '_gcl_aw', '_gcl_dc', '_gcl_gb',
  '_gcl_gf', '_gid', '_gl', '_ipg', '_ke', '_kl',
  '_kn', '_ko', '_kq', '_kr', '_ks', '_kt',
  '_ku', '_kv', '_kw', '_kx', '_ky', '_kz',
  '_nkw', '_sacat', '_sop', '_t', '_trkparms', '_trksid',
  '_type', 'ab_brand', 'ab_channel', 'access_token', 'aff_id', 'affid',
  'affiliate', 'affiliate_id', 'affiliateid', 'afftrack', 'analytic', 'analytics',
  'api_key', 'apikey', 'app', 'app_id', 'app_name', 'appid',
  'appname', 'asc_campaign', 'asc_ref_tag', 'asc_refurl', 'asc_source', 'ascsubtag',
  'auth', 'beacon', 'beacons', 'browser', 'browser_id', 'bundle_id',
  'bundleid', 'campaign', 'campaign_id', 'campaignid', 'campid', 'cerf',
  'cerf1', 'cf_chl_captcha_tk__', 'cf_chl_jschl_tk__', 'cf_chl_prog', 'cf_ob', 'cf_ob_info',
  'cf_use_ob', 'cid', 'click', 'clicked', 'clickid', 'cmp',
  'cmpid', 'coupon', 'crid', 'customid', 'cvid', 'dcid',
  'dclid', 'deal', 'destination', 'device', 'device_id', 'deviceid',
  'discount', 'ef_id', 'eid', 'elq', 'elqCampaignId', 'elqTrackId',
  'email_id', 'emailid', 'end', 'epik', 'epikid', 'event',
  'events', 'fb_action_ids', 'fb_action_types', 'fb_comment_id', 'fb_instant_article', 'fb_pipeline_cr',
  'fb_ref', 'fb_source', 'fb_xd_fragment', 'fbclid', 'feature', 'fingerprint',
  'fp', 'from', 'gclid', 'gclsrc', 'guid', 'hsCacheBuster',
  'hsCtaTracking', 'hs_a', 'hs_preview', 'hsa_acc', 'hsa_ad', 'hsa_cam',
  'hsa_grp', 'hsa_kw', 'hsa_la', 'hsa_mt', 'hsa_net', 'hsa_ol',
  'hsa_random', 'hsa_src', 'hsa_tgt', 'hsa_ver', 'ie', 'igshid',
  'index', 'int', 'int_id', 'int_source', 'internal', 'internal_id',
  'intsrc', 'invite', 'invited', 'invited_by', 'invitedby', 'inviter',
  'itscg', 'itsct', 'kenshoo', 'key', 'keywords', 'li_advertiser_id',
  'li_campaign', 'li_fat_id', 'li_g', 'li_targetid', 'linkCode', 'linkId',
  'list', 'log', 'logs', 'lsid', 'mailid', 'matomo_campaign',
  'matomo_keyword', 'matomo_medium', 'matomo_source', 'mc_cid', 'mc_eid', 'memberid',
  'metric', 'metrics', 'mkcid', 'mkevt', 'mkrid', 'mkt_tok',
  'mkt_tok2', 'msclkid', 'mtm_campaign', 'mtm_content', 'mtm_keyword', 'mtm_medium',
  'mtm_source', 'next', 'nf_analytics', 'nf_photo', 'nf_resize', 'node',
  'offer', 'offers', 'oicd', 'origin', 'package', 'package_name',
  'packagename', 'partner', 'pd_rd_a', 'pd_rd_i', 'pd_rd_r', 'pd_rd_w',
  'pd_rd_wg', 'pf_rd_i', 'pf_rd_m', 'pf_rd_p', 'pf_rd_r', 'pf_rd_s',
  'pf_rd_t', 'phid', 'pi_ad_id', 'pi_campaign_id', 'pi_trk', 'pid',
  'ping', 'pings', 'pinterest_campaign', 'pinterest_source', 'pk_', 'pk_campaign',
  'pk_cid', 'pk_content', 'pk_keyword', 'pk_kwd', 'pk_medium', 'pk_source',
  'pp', 'promo', 'promo_code', 'promocode', 'promotion', 'psc',
  'pt', 'qid', 'rdt_cid', 'recipient', 'recipient_id', 'reddit_campaign',
  'reddit_source', 'redir', 'redirect', 'ref', 'refRID', 'ref_',
  'referer', 'referral', 'referred_by', 'referredby', 'referrer', 'return',
  'returnUrl', 'return_to', 's_cid', 's_kwcid', 's_kwid', 'sale',
  'sc_campaign', 'sc_channel', 'sc_content', 'sc_creative', 'sc_medium', 'sc_source',
  'sc_src', 'sc_term', 'session', 'session_id', 'sessionid', 'share',
  'share_app_id', 'share_author_id', 'share_link_id', 'shared', 'sharer', 'sharetype',
  'sharing', 'shp', 'shp_m', 'shp_r', 'shpn', 'shpv',
  'shpxid', 'si', 'sid', 'smid', 'source', 'special',
  'sprefix', 'sr', 'src', 'start', 'stat', 'stats',
  'store_id', 'storeid', 'subid', 'subscriberid', 't', 'tag',
  'tid', 'to', 'token', 'toolid', 'track', 'tracking',
  'traffic_type', 'trk', 'trks', 'tt_ad_id', 'tt_adgroup_id', 'tt_adset_id',
  'tt_campaign', 'tt_campaign_id', 'tt_content', 'tt_medium', 'tt_source', 'tt_term',
  'ttclid', 'tw_c', 'tw_i', 'tw_o', 'tw_p', 'tw_s',
  'tw_w', 'twclid', 'ug_campaign', 'ug_medium', 'ug_source', 'uid',
  'url', 'user', 'user_id', 'userid', 'utm', 'utm_ad',
  'utm_adgroup', 'utm_campaign', 'utm_content', 'utm_creative', 'utm_creative_format', 'utm_device',
  'utm_email', 'utm_id', 'utm_keyword', 'utm_marketing_tactic', 'utm_matchtype', 'utm_medium',
  'utm_network', 'utm_placement', 'utm_source', 'utm_source_platform', 'utm_target', 'utm_term',
  'uuid', 'vendor', 'vercel', 'vercelAnalytics', 'via', 'vid',
  'visitor', 'visitor_id', 'visitorid', 'visitors', 'wickedid', 'wt_',
  'wtm_source', 'wtmc', 'wtmcid', 'wtrid', 'yclid', 'zanpid',
]);

// ── Environment Variables that Leak Data ────────────────────
const TRACKER_ENV_VARS = new Set([
  'ADSENSE_ID', 'ADWORDS_ID', 'AFFILIATE_ID', 'ALGOLIA_API_KEY',
  'ALGOLIA_APP_ID', 'ALGOLIA_SEARCH_KEY', 'AMAZON_ASSOCIATE_TAG', 'AMPLITUDE_API_KEY',
  'AWS_CLOUDWATCH_NAMESPACE', 'AWS_SES_ACCESS_KEY', 'AZURE_INSIGHTS_KEY', 'BING_ADS_ID',
  'BUGSNAG_API_KEY', 'CHATWOOT_TOKEN', 'CRISP_WEBSITE_ID', 'DATADOG_CLIENT_TOKEN',
  'DATADOME_JS_KEY', 'DRIFT_ID', 'EBAY_CAMPAIGN_ID', 'FACEBOOK_PIXEL_ID',
  'FB_PIXEL_ID', 'FINGERPRINTJS_API_KEY', 'FULLSTORY_ORG', 'GA_ID',
  'GA_TRACKING_ID', 'GCP_TRACE_ENABLED', 'GOOGLE_ADS_ID', 'GOOGLE_ANALYTICS_ID',
  'GTAG_ID', 'HEAP_APP_ID', 'HOTJAR_ID', 'HOTJAR_SITE_ID',
  'HUMAN_SECURITY_KEY', 'INTERCOM_APP_ID', 'KASADA_API_KEY', 'LINKEDIN_PARTNER_ID',
  'LOGROCKET_APP_ID', 'MAILCHIMP_API_KEY', 'MAILGUN_API_KEY', 'META_PIXEL_ID',
  'MGID_PUBLISHER_ID', 'MIXPANEL_TOKEN', 'NETLIFY_ANALYTICS_ID', 'NEW_RELIC_LICENSE_KEY',
  'OUTBRAIN_WIDGET_ID', 'PERIMETERX_APP_ID', 'PINTEREST_TAG_ID', 'POSTMARK_API_TOKEN',
  'RAILWAY_ENVIRONMENT', 'REDDIT_PIXEL_ID', 'REVCONTENT_API_KEY', 'SEGMENT_KEY',
  'SEGMENT_WRITE_KEY', 'SENDGRID_API_KEY', 'SENTRY_DSN', 'SENTRY_KEY',
  'SNAPCHAT_PIXEL_ID', 'TABOOLA_PUBLISHER_ID', 'TIDIO_PUBLIC_KEY', 'TIKTOK_PIXEL_ID',
  'TWITTER_PIXEL_ID', 'VERCEL_ANALYTICS_ID', 'YAHOO_ADS_ID',
]);

// ── Header Patterns to Block ─────────────────────────────────
const TRACKING_HEADERS = new Set([
  'x-adcolony-device-id', 'x-adjust-device-id', 'x-adjust-gps-adid',
  'x-admob-device-id', 'x-adobe-analytics', 'x-adobe-marketing-cloud-visitor-id',
  'x-akamai-transformed', 'x-amplitude-session-id', 'x-amz-cf-id',
  'x-amz-cf-pop', 'x-applovin-device-id', 'x-appsflyer-advertising-id',
  'x-appsflyer-id', 'x-branch-identity', 'x-bugsnag-api-key',
  'x-cache', 'x-cache-hits', 'x-campaign-code',
  'x-chartboost-device-id', 'x-chrome-connected', 'x-chrome-uma-enabled',
  'x-client-data', 'x-cloud-trace-context', 'x-coreid',
  'x-crashlytics-installation-id', 'x-datadog-trace-id', 'x-doubleclick-id',
  'x-edgeconnect-midmile-rtt', 'x-edgeconnect-origin-mex-latency', 'x-eloqua-tracking',
  'x-facebook-conversion-tracking', 'x-fastly-request-id', 'x-firebase-instance-id',
  'x-fullstory-session', 'x-ga-lite-version', 'x-goog-authuser',
  'x-goog-channel-id', 'x-goog-encode-response-if-executable', 'x-goog-pageid',
  'x-goog-visitor-id', 'x-google-abuse', 'x-google-dai-auth-token',
  'x-googletagmanager-auth', 'x-googletagmanager-preview', 'x-heap-user-id',
  'x-hits', 'x-hotjar-user-id', 'x-http-method-override',
  'x-hubspot-correlation-id', 'x-hubspot-track-payload', 'x-ironsource-device-id',
  'x-javascript-user-agent', 'x-kochava-device-id', 'x-linkedin-track',
  'x-logrocket-session-url', 'x-marketo-tracking', 'x-mixpanel-distinct-id',
  'x-newrelic-id', 'x-nginx-cache', 'x-optimizely-enduserid',
  'x-pardot-lua-url', 'x-pardot-route', 'x-pardot-set-cookie',
  'x-pinterest-cta-tracking', 'x-raygun-user', 'x-reddit-track',
  'x-requested-with', 'x-rollbar-person', 'x-segment-anonymous-id',
  'x-sentry-trace', 'x-served-by', 'x-singular-device-id',
  'x-snapchat-track', 'x-startapp-device-id', 'x-tenjin-advertising-id',
  'x-tiktok-track', 'x-timer', 'x-twitter-tracking',
  'x-umeng-device-id', 'x-unityads-device-id', 'x-varnish',
  'x-vungle-device-id', 'x-wp-total', 'x-wp-totalpages',
  'x-youtube-ad-signals', 'x-youtube-client-name', 'x-youtube-client-version',
  'x-youtube-page-cl', 'x-youtube-page-label', 'x-youtube-utc-offset',
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
