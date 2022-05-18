//remote address: 100.12.115.15
//ip: v4
//port: 50100
//last seen ip: 100.12.115.15
//last seen age: 0
function FindProxyForURL(url, host) {
	//FROM RULE: BYPASS:dnsDomainIs(host, "login.microsoftonline.com")
	if(dnsDomainIs(host, "login.microsoftonline.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "login.windows.net")
	if(dnsDomainIs(host, "login.windows.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "quran.com")
	if(dnsDomainIs(host, "quran.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "googleapis.com")
	if(dnsDomainIs(host, "googleapis.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "googleadservices.com")
	if(dnsDomainIs(host, "googleadservices.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "ytimg.com")
	if(dnsDomainIs(host, "ytimg.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "amazonaws.com")
	if(dnsDomainIs(host, "amazonaws.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "quranicaudio.com")
	if(dnsDomainIs(host, "quranicaudio.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "freeconferencecall.com")
	if(dnsDomainIs(host, "freeconferencecall.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "skypeassets.com")
	if(dnsDomainIs(host, "skypeassets.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "skype.net")
	if(dnsDomainIs(host, "skype.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "cdn.content.prod.cms.msn.com")
	if(dnsDomainIs(host, "cdn.content.prod.cms.msn.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gate.hockeyapp.net")
	if(dnsDomainIs(host, "gate.hockeyapp.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mobile.pipe.aria.microsoft.com")
	if(dnsDomainIs(host, "mobile.pipe.aria.microsoft.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "odc.officeapps.live.com")
	if(dnsDomainIs(host, "odc.officeapps.live.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "webdir.online.lync.com")
	if(dnsDomainIs(host, "webdir.online.lync.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "edge.skype.com")
	if(dnsDomainIs(host, "edge.skype.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "config.edge.skype.com")
	if(dnsDomainIs(host, "config.edge.skype.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "meet.lync.com")
	if(dnsDomainIs(host, "meet.lync.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "login.live.com")
	if(dnsDomainIs(host, "login.live.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "data.flurry.com")
	if(dnsDomainIs(host, "data.flurry.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "dc.trouter.io")
	if(dnsDomainIs(host, "dc.trouter.io")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "vo.msecnd.net")
	if(dnsDomainIs(host, "vo.msecnd.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "account.azureedge.net")
	if(dnsDomainIs(host, "account.azureedge.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "skypesmssfe.trafficmanager.net")
	if(dnsDomainIs(host, "skypesmssfe.trafficmanager.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "msauth.net")
	if(dnsDomainIs(host, "msauth.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "events.data.microsoft.com")
	if(dnsDomainIs(host, "events.data.microsoft.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "browser.pipe.aria.microsoft.com")
	if(dnsDomainIs(host, "browser.pipe.aria.microsoft.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "templateservice.office.com")
	if(dnsDomainIs(host, "templateservice.office.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "lync.com")
	if(dnsDomainIs(host, "lync.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "shamela.ws")
	if(dnsDomainIs(host, "shamela.ws")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"webdir.online.lync.com")
	if(dnsDomainIs(host,"webdir.online.lync.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"skype.com")
	if(dnsDomainIs(host,"skype.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"skype.net")
	if(dnsDomainIs(host,"skype.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"login.live.com")
	if(dnsDomainIs(host,"login.live.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"data.flurry.com")
	if(dnsDomainIs(host,"data.flurry.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"dc.trouter.io")
	if(dnsDomainIs(host,"dc.trouter.io")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"vo.msecnd.net")
	if(dnsDomainIs(host,"vo.msecnd.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"odc.officeapps.live.com")
	if(dnsDomainIs(host,"odc.officeapps.live.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"gate.hockeyapp.net")
	if(dnsDomainIs(host,"gate.hockeyapp.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"account.azureedge.net")
	if(dnsDomainIs(host,"account.azureedge.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"skypesmssfe.trafficmanager.net")
	if(dnsDomainIs(host,"skypesmssfe.trafficmanager.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"edge.skype.com")
	if(dnsDomainIs(host,"edge.skype.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"msauth.net")
	if(dnsDomainIs(host,"msauth.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"events.data.microsoft.com")
	if(dnsDomainIs(host,"events.data.microsoft.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"browser.pipe.aria.microsoft.com")
	if(dnsDomainIs(host,"browser.pipe.aria.microsoft.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"templateservice.office.com")
	if(dnsDomainIs(host,"templateservice.office.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"meet.lync.com")
	if(dnsDomainIs(host,"meet.lync.com")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "20.202.20.20", "255.255.0.0")
	if(isInNet(dnsResolve(host), "20.202.20.20", "255.255.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "20.202.20.37", "255.255.0.0")
	if(isInNet(dnsResolve(host), "20.202.20.37", "255.255.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "20.202.20.13", "255.255.0.0")
	if(isInNet(dnsResolve(host), "20.202.20.13", "255.255.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"clients.gateway.messenger.live.ccom")
	if(dnsDomainIs(host,"clients.gateway.messenger.live.ccom")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"clients3.google.com")
	if(dnsDomainIs(host,"clients3.google.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"options.skype.com")
	if(dnsDomainIs(host,"options.skype.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"people.skype.com")
	if(dnsDomainIs(host,"people.skype.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"in.appcenter.ms")
	if(dnsDomainIs(host,"in.appcenter.ms")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"inappcheck.itunes.com")
	if(dnsDomainIs(host,"inappcheck.itunes.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"msgsearch.skype.com")
	if(dnsDomainIs(host,"msgsearch.skype.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"pnv.skype.com")
	if(dnsDomainIs(host,"pnv.skype.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"azscus1-client-s.gateway.messenger.live.com")
	if(dnsDomainIs(host,"azscus1-client-s.gateway.messenger.live.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"api.asm.skype.com")
	if(dnsDomainIs(host,"api.asm.skype.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"api.skype.com")
	if(dnsDomainIs(host,"api.skype.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"gateway.messenger.live.com")
	if(dnsDomainIs(host,"gateway.messenger.live.com")) return "DIRECT";

	//FROM RULE: BLOCK:dnsDomainIs(host,"avatar.skype.com")
	if(dnsDomainIs(host,"avatar.skype.com")) return "PROXY 0.0.0.0:1234";

	//FROM RULE: BLOCK:dnsDomainIs(host,"skypegraph.skype.com")
	if(dnsDomainIs(host,"skypegraph.skype.com")) return "PROXY 0.0.0.0:1234";

	//FROM RULE: BLOCK:dnsDomainIs(host, "appldnld.apple.com")
	if(dnsDomainIs(host, "appldnld.apple.com")) return "PROXY 0.0.0.0:1234";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gtnpios.gentechsolution.com")
	if(dnsDomainIs(host, "gtnpios.gentechsolution.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gentechsolution.com")
	if(dnsDomainIs(host, "gentechsolution.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "rndsoftwaregroup.com")
	if(dnsDomainIs(host, "rndsoftwaregroup.com")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "127.0.0.1", "255.0.0.0")
	if(isInNet(dnsResolve(host), "127.0.0.1", "255.0.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0")
	if(isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "10.0.0.0", "10.255.255.255")
	if(isInNet(dnsResolve(host), "10.0.0.0", "10.255.255.255")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "100.0.0.0", "100.255.255.255")
	if(isInNet(dnsResolve(host), "100.0.0.0", "100.255.255.255")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "10.0.2.55", "255.0.0.0")
	if(isInNet(dnsResolve(host), "10.0.2.55", "255.0.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0")
	if(isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0")
	if(isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "167.114.178.167", "255.255.0.0")
	if(isInNet(dnsResolve(host), "167.114.178.167", "255.255.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "touchtype-fluency.com")
	if(dnsDomainIs(host, "touchtype-fluency.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "rndsoftwaregroup.com")
	if(dnsDomainIs(host, "rndsoftwaregroup.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gthelps.com")
	if(dnsDomainIs(host, "gthelps.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "livigent.com")
	if(dnsDomainIs(host, "livigent.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gentechsolution.com")
	if(dnsDomainIs(host, "gentechsolution.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "rndsg.com")
	if(dnsDomainIs(host, "rndsg.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "rndsg.info")
	if(dnsDomainIs(host, "rndsg.info")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "crashlytics.com")
	if(dnsDomainIs(host, "crashlytics.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "decide.mixpanel.com")
	if(dnsDomainIs(host, "decide.mixpanel.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "api-vzw-dis.asurionmobile.com")
	if(dnsDomainIs(host, "api-vzw-dis.asurionmobile.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "samsungapps.com")
	if(dnsDomainIs(host, "samsungapps.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "secb2b.com")
	if(dnsDomainIs(host, "secb2b.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "wdsglobal.com")
	if(dnsDomainIs(host, "wdsglobal.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mms.sprintpcs.com")
	if(dnsDomainIs(host, "mms.sprintpcs.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "68.28.31.76")
	if(dnsDomainIs(host, "68.28.31.76")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "69.78.88.6")
	if(dnsDomainIs(host, "69.78.88.6")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mobile.att.net")
	if(dnsDomainIs(host, "mobile.att.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "vtext.com")
	if(dnsDomainIs(host, "vtext.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "vzwpix.com")
	if(dnsDomainIs(host, "vzwpix.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mypixmessages.com")
	if(dnsDomainIs(host, "mypixmessages.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "vzmessages.com")
	if(dnsDomainIs(host, "vzmessages.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "t-mobile.com")
	if(dnsDomainIs(host, "t-mobile.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "metropcs.com")
	if(dnsDomainIs(host, "metropcs.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mmsmvno.com")
	if(dnsDomainIs(host, "mmsmvno.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mobile.att.net")
	if(dnsDomainIs(host, "mobile.att.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mms.vtext.com")
	if(dnsDomainIs(host, "mms.vtext.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "myvzw.com")
	if(dnsDomainIs(host, "myvzw.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "vzw.com")
	if(dnsDomainIs(host, "vzw.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gmail.com")
	if(dnsDomainIs(host, "gmail.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "maps.google.com")
	if(dnsDomainIs(host, "maps.google.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mobilemaps-pa.googleapis.com")
	if(dnsDomainIs(host, "mobilemaps-pa.googleapis.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "maps.googleapis.com")
	if(dnsDomainIs(host, "maps.googleapis.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "accounts.google.com")
	if(dnsDomainIs(host, "accounts.google.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mail.google.com")
	if(dnsDomainIs(host, "mail.google.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "clients4.google.com")
	if(dnsDomainIs(host, "clients4.google.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "ggpht.com")
	if(dnsDomainIs(host, "ggpht.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gvt1.com")
	if(dnsDomainIs(host, "gvt1.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "play.googleapis.com")
	if(dnsDomainIs(host, "play.googleapis.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "lh*.googleusercontent.com")
	if(dnsDomainIs(host, "lh*.googleusercontent.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "ci*.googleusercontent.com")
	if(dnsDomainIs(host, "ci*.googleusercontent.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "googleapis.com")
	if(dnsDomainIs(host, "googleapis.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "maps.gstatic.com")
	if(dnsDomainIs(host, "maps.gstatic.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*maps.gstatic.com*")
	if(shExpMatch(url, "*maps.gstatic.com*")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "waze.com")
	if(dnsDomainIs(host, "waze.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "rt.waze.com")
	if(dnsDomainIs(host, "rt.waze.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "android.clients.google.com")
	if(dnsDomainIs(host, "android.clients.google.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mx.google.com")
	if(dnsDomainIs(host, "mx.google.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gstatic.com")
	if(dnsDomainIs(host, "gstatic.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "analytics.com")
	if(dnsDomainIs(host, "analytics.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "amazonaws.com")
	if(dnsDomainIs(host, "amazonaws.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "history.google.com")
	if(dnsDomainIs(host, "history.google.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "graph.facebook.com")
	if(dnsDomainIs(host, "graph.facebook.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "glympse.com")
	if(dnsDomainIs(host, "glympse.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "accounts.youtube.com")
	if(dnsDomainIs(host, "accounts.youtube.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "settings.google.com")
	if(dnsDomainIs(host, "settings.google.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "myaccount.google.com")
	if(dnsDomainIs(host, "myaccount.google.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "cloudfront.net")
	if(dnsDomainIs(host, "cloudfront.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "java.net")
	if(dnsDomainIs(host, "java.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "chase.com")
	if(dnsDomainIs(host, "chase.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "chasecdn.com")
	if(dnsDomainIs(host, "chasecdn.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "jpmc-consumer-acceptor.zimperium.com")
	if(dnsDomainIs(host, "jpmc-consumer-acceptor.zimperium.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "yahoomail.com")
	if(dnsDomainIs(host, "yahoomail.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mail.yimg.com")
	if(dnsDomainIs(host, "mail.yimg.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mail.vip.gq1.yahoo.com")
	if(dnsDomainIs(host, "mail.vip.gq1.yahoo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mail.yahoo.com")
	if(dnsDomainIs(host, "mail.yahoo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "login.yahoo.com")
	if(dnsDomainIs(host, "login.yahoo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "geo.yahoo.com")
	if(dnsDomainIs(host, "geo.yahoo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "api.login.yahoo.com")
	if(dnsDomainIs(host, "api.login.yahoo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "m.yap.yahoo.com")
	if(dnsDomainIs(host, "m.yap.yahoo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "apis.mail.yahoo.com")
	if(dnsDomainIs(host, "apis.mail.yahoo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "dl-mail.ymail.com")
	if(dnsDomainIs(host, "dl-mail.ymail.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "s.yimg.com")
	if(shExpMatch(url, "s.yimg.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "guce.yahoo.com")
	if(dnsDomainIs(host, "guce.yahoo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "config.mobile.yahoo.com")
	if(dnsDomainIs(host, "config.mobile.yahoo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "udc.yahoo.com")
	if(dnsDomainIs(host, "udc.yahoo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "opensignal.com")
	if(dnsDomainIs(host, "opensignal.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "api.parse.com")
	if(dnsDomainIs(host, "api.parse.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "js2.yimg.com")
	if(dnsDomainIs(host, "js2.yimg.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "i1.yimg.com")
	if(dnsDomainIs(host, "i1.yimg.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "us.bc.yahoo.com")
	if(dnsDomainIs(host, "us.bc.yahoo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "us.a2.yimg.com")
	if(dnsDomainIs(host, "us.a2.yimg.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "ads.yimg.com")
	if(dnsDomainIs(host, "ads.yimg.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "l.yimg.com")
	if(dnsDomainIs(host, "l.yimg.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "northeastbank.com")
	if(dnsDomainIs(host, "northeastbank.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "digitalinsight.com")
	if(dnsDomainIs(host, "digitalinsight.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "necommunitybankonline.com")
	if(dnsDomainIs(host, "necommunitybankonline.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "necb.com")
	if(dnsDomainIs(host, "necb.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "samsunghelpcenter.com")
	if(dnsDomainIs(host, "samsunghelpcenter.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "googletagmanager.com")
	if(dnsDomainIs(host, "googletagmanager.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "social.yahooapis.com")
	if(dnsDomainIs(host, "social.yahooapis.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "sense360eng.com")
	if(dnsDomainIs(host, "sense360eng.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "bugsnag.com")
	if(dnsDomainIs(host, "bugsnag.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "slack-core.com")
	if(dnsDomainIs(host, "slack-core.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gravatar.com")
	if(dnsDomainIs(host, "gravatar.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "slackhq.com")
	if(dnsDomainIs(host, "slackhq.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "slack.global.ssl.fastly.net")
	if(dnsDomainIs(host, "slack.global.ssl.fastly.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "online-metrix.net")
	if(dnsDomainIs(host, "online-metrix.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "riteaid.com")
	if(dnsDomainIs(host, "riteaid.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "accuweather.com")
	if(dnsDomainIs(host, "accuweather.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "docs.google.com")
	if(dnsDomainIs(host, "docs.google.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "drive.google.com")
	if(dnsDomainIs(host, "drive.google.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "googledrive.com")
	if(dnsDomainIs(host, "googledrive.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mail-attachment.googleusercontent.com")
	if(dnsDomainIs(host, "mail-attachment.googleusercontent.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "cl*.apple.com")
	if(dnsDomainIs(host, "cl*.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gspe*-ssl.ls.apple.com")
	if(dnsDomainIs(host, "gspe*-ssl.ls.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gsp*-ssl.ls.apple.com")
	if(dnsDomainIs(host, "gsp*-ssl.ls.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gsp*-ssl.apple.com")
	if(dnsDomainIs(host, "gsp*-ssl.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gs-loc.apple.com")
	if(dnsDomainIs(host, "gs-loc.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gsp*-ssl-locus.ls.apple.com")
	if(dnsDomainIs(host, "gsp*-ssl-locus.ls.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "siri.apple.com")
	if(dnsDomainIs(host, "siri.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "profile.gc.apple.com")
	if(dnsDomainIs(host, "profile.gc.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "sq-device.apple.com")
	if(dnsDomainIs(host, "sq-device.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "valid.apple.com")
	if(dnsDomainIs(host, "valid.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "tbsc.apple.com")
	if(dnsDomainIs(host, "tbsc.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gsp*-ssl-background.ls.apple.com")
	if(dnsDomainIs(host, "gsp*-ssl-background.ls.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "search.itunes.apple.com")
	if(dnsDomainIs(host, "search.itunes.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "uts-api.itunes.apple.com")
	if(dnsDomainIs(host, "uts-api.itunes.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "audio.itunes.apple.com")
	if(dnsDomainIs(host, "audio.itunes.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "itunes.apple.com")
	if(dnsDomainIs(host, "itunes.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "music.itunes.apple.com")
	if(dnsDomainIs(host, "music.itunes.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "itunes.apple.com")
	if(dnsDomainIs(host, "itunes.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "xp.apple.com")
	if(shExpMatch(url, "xp.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "swscan.apple.com")
	if(shExpMatch(url, "swscan.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "configuration.apple.com")
	if(shExpMatch(url, "configuration.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "init-p01md.apple.com")
	if(shExpMatch(url, "init-p01md.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "lookup-api.apple.com")
	if(shExpMatch(url, "lookup-api.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*cl*.apple.com*")
	if(shExpMatch(url, "*cl*.apple.com*")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "apple.com")
	if(shExpMatch(url, "apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "gspe*-ssl.ls.apple.com")
	if(shExpMatch(url, "gspe*-ssl.ls.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "gsp*-ssl.ls.apple.com")
	if(shExpMatch(url, "gsp*-ssl.ls.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "gsp*-ssl.apple.com")
	if(shExpMatch(url, "gsp*-ssl.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "gs-loc.apple.com")
	if(shExpMatch(url, "gs-loc.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "gsp*-ssl-locus.ls.apple.com")
	if(shExpMatch(url, "gsp*-ssl-locus.ls.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "idmsa.apple.com")
	if(shExpMatch(url, "idmsa.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "icloud.cdn-apple.com")
	if(shExpMatch(url, "icloud.cdn-apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "gsas.apple.com")
	if(shExpMatch(url, "gsas.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "finance-app.itunes.apple.com")
	if(shExpMatch(url, "finance-app.itunes.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "iidentity.ess.apple.com")
	if(shExpMatch(url, "iidentity.ess.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "profile.ess.apple.com")
	if(shExpMatch(url, "profile.ess.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "configuration.apple.com")
	if(shExpMatch(url, "configuration.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "identity.apple.com")
	if(shExpMatch(url, "identity.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "gg*.apple.com")
	if(shExpMatch(url, "gg*.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "me.com")
	if(shExpMatch(url, "me.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "gsa.apple.com")
	if(shExpMatch(url, "gsa.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "apple.com")
	if(dnsDomainIs(host, "apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "music.apple.com")
	if(shExpMatch(url, "music.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "ocsp.apple.com")
	if(shExpMatch(url, "ocsp.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "init.ess.apple.com")
	if(shExpMatch(url, "init.ess.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "push.apple.com")
	if(shExpMatch(url, "push.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*itunes.apple.com*")
	if(shExpMatch(url, "*itunes.apple.com*")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "genius-*.itunes.apple.com")
	if(shExpMatch(url, "genius-*.itunes.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "icloud.com")
	if(shExpMatch(url, "icloud.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "appleid.apple.com")
	if(shExpMatch(url, "appleid.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "appldnld.apple.com")
	if(shExpMatch(url, "appldnld.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "albert.apple.com")
	if(shExpMatch(url, "albert.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "init-p01md.apple.com")
	if(shExpMatch(url, "init-p01md.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "skl.apple.com")
	if(shExpMatch(url, "skl.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "appleid.cdn-apple.com")
	if(shExpMatch(url, "appleid.cdn-apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "iphone-ld.apple.com")
	if(shExpMatch(url, "iphone-ld.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "carrierbundle.itunes.apple.com")
	if(shExpMatch(url, "carrierbundle.itunes.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*deimos3.apple.com*")
	if(shExpMatch(url, "*deimos3.apple.com*")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "finance-app.itunes.apple.com")
	if(shExpMatch(url, "finance-app.itunes.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "fapi.music.apple.com")
	if(shExpMatch(url, "fapi.music.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "itunesu.itunes.apple.com")
	if(shExpMatch(url, "itunesu.itunes.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "play-edge.itunes.apple.com")
	if(shExpMatch(url, "play-edge.itunes.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*static.ess.apple.com*")
	if(shExpMatch(url, "*static.ess.apple.com*")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "itunes.apple.com")
	if(shExpMatch(url, "itunes.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "cf.iadsdk.apple.com")
	if(shExpMatch(url, "cf.iadsdk.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "lcdn-locator.apple.com")
	if(shExpMatch(url, "lcdn-locator.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "usnyc.icloud-content.com")
	if(shExpMatch(url, "usnyc.icloud-content.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "aidc.apple.com")
	if(shExpMatch(url, "aidc.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "humb.apple.com")
	if(shExpMatch(url, "humb.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "detxl-edge.iclo-content.com")
	if(shExpMatch(url, "detxl-edge.iclo-content.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "identity.ess.apple.com")
	if(shExpMatch(url, "identity.ess.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "paymentservices.apple.com")
	if(shExpMatch(url, "paymentservices.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*cl2.apple.com*")
	if(shExpMatch(url, "*cl2.apple.com*")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "smp-device.apple.com")
	if(shExpMatch(url, "smp-device.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "smp-device-asset.apple.com")
	if(shExpMatch(url, "smp-device-asset.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*smp-device-content.apple.com*")
	if(shExpMatch(url, "*smp-device-content.apple.com*")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "configuration.apple.com")
	if(dnsDomainIs(host, "configuration.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "carrierbundle.itunes.apple.com")
	if(dnsDomainIs(host, "carrierbundle.itunes.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "sf-api-token-service.itunes.apple.com")
	if(dnsDomainIs(host, "sf-api-token-service.itunes.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "se-edge.itunes.apple.com")
	if(dnsDomainIs(host, "se-edge.itunes.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "appleid.apple.com")
	if(dnsDomainIs(host, "appleid.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "cf.iadsdk.apple.com")
	if(dnsDomainIs(host, "cf.iadsdk.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "edge.icloud.com")
	if(dnsDomainIs(host, "edge.icloud.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "usnyc-edge-030.icloud-content.com")
	if(dnsDomainIs(host, "usnyc-edge-030.icloud-content.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "init.push.apple.com")
	if(dnsDomainIs(host, "init.push.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "us-east-1.blobstore.apple.com")
	if(dnsDomainIs(host, "us-east-1.blobstore.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "guzzoni.apple.com")
	if(dnsDomainIs(host, "guzzoni.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gateway-carry.icloud.com.com")
	if(dnsDomainIs(host, "gateway-carry.icloud.com.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "detxl-edge.icloud-content.com")
	if(dnsDomainIs(host, "detxl-edge.icloud-content.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "bag.itunes.apple.com")
	if(dnsDomainIs(host, "bag.itunes.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "kt-prod.apple.com")
	if(dnsDomainIs(host, "kt-prod.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "ca.iadsdk.apple.com")
	if(dnsDomainIs(host, "ca.iadsdk.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "api-glb-nyc.smoot.apple.com")
	if(dnsDomainIs(host, "api-glb-nyc.smoot.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "api.smoot.apple.com")
	if(dnsDomainIs(host, "api.smoot.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "ca.iadsdk.apple.com")
	if(dnsDomainIs(host, "ca.iadsdk.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "daypass.smoot.apple.com")
	if(dnsDomainIs(host, "daypass.smoot.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "ssl.gstatic.com")
	if(dnsDomainIs(host, "ssl.gstatic.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*gmail.com*")
	if(shExpMatch(url, "*gmail.com*")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*mail.google.com*")
	if(shExpMatch(url, "*mail.google.com*")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*inbox.google.com*")
	if(shExpMatch(url, "*inbox.google.com*")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*ocsp.digicert.com*")
	if(shExpMatch(url, "*ocsp.digicert.com*")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*accounts.google.com*")
	if(shExpMatch(url, "*accounts.google.com*")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*myaccount.google.com*")
	if(shExpMatch(url, "*myaccount.google.com*")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*gmail.google.com*")
	if(shExpMatch(url, "*gmail.google.com*")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*gmail.com*")
	if(shExpMatch(url, "*gmail.com*")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*google.com/loc/m/api*")
	if(shExpMatch(url, "*google.com/loc/m/api*")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*google.com/glm/mmap*")
	if(shExpMatch(url, "*google.com/glm/mmap*")) return "DIRECT";

	//FROM RULE: BLOCK:shExpMatch(url, "*lh*.googleusercontent.com*")
	if(shExpMatch(url, "*lh*.googleusercontent.com*")) return "PROXY 0.0.0.0:1234";

	//FROM RULE: BYPASS:shExpMatch(url, "*inbox.google.com*")
	if(shExpMatch(url, "*inbox.google.com*")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*nc-pod5-smp-device.apple.com*")
	if(shExpMatch(url, "*nc-pod5-smp-device.apple.com*")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*gil.apple.com*")
	if(shExpMatch(url, "*gil.apple.com*")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gil.apple.com")
	if(dnsDomainIs(host, "gil.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "apple.smtp.mail.yahoo.com")
	if(dnsDomainIs(host, "apple.smtp.mail.yahoo.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "newaccountredirectdomain.apple.com")
	if(shExpMatch(url, "newaccountredirectdomain.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "connectivitycheck.gstatic.com")
	if(shExpMatch(url, "connectivitycheck.gstatic.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "siri.apple.com")
	if(shExpMatch(url, "siri.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "setup.icloud.com")
	if(shExpMatch(url, "setup.icloud.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "api.weather.com")
	if(shExpMatch(url, "api.weather.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "smtp.gmail.com")
	if(dnsDomainIs(host, "smtp.gmail.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mail.me.com")
	if(dnsDomainIs(host, "mail.me.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "smtp.office365.com")
	if(dnsDomainIs(host, "smtp.office365.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "outlook.office365.com")
	if(dnsDomainIs(host, "outlook.office365.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "imap-mail.outlook.com")
	if(dnsDomainIs(host, "imap-mail.outlook.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "smtp-mail.outlook.com")
	if(dnsDomainIs(host, "smtp-mail.outlook.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "smtp.yahoo.com")
	if(dnsDomainIs(host, "smtp.yahoo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mail.yahoo.com")
	if(dnsDomainIs(host, "mail.yahoo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "login.yahoo.com")
	if(dnsDomainIs(host, "login.yahoo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "api.login.yahoo.com")
	if(dnsDomainIs(host, "api.login.yahoo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "ymail.com")
	if(dnsDomainIs(host, "ymail.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "imap.secureserver.net")
	if(dnsDomainIs(host, "imap.secureserver.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "smtpout.secureserver.net")
	if(dnsDomainIs(host, "smtpout.secureserver.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "appsitemsuggest-pa.googleapis.com")
	if(dnsDomainIs(host, "appsitemsuggest-pa.googleapis.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "appldnld.apple.com")
	if(dnsDomainIs(host, "appldnld.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "icloud.com")
	if(dnsDomainIs(host, "icloud.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "icloud-content.com")
	if(dnsDomainIs(host, "icloud-content.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "setup.icloud.com")
	if(dnsDomainIs(host, "setup.icloud.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "ocsp.apple.com")
	if(dnsDomainIs(host, "ocsp.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "aidc.apple.com")
	if(dnsDomainIs(host, "aidc.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "swscan.apple.com")
	if(dnsDomainIs(host, "swscan.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "iadsdk.apple.com")
	if(dnsDomainIs(host, "iadsdk.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "idmsa.apple.com")
	if(dnsDomainIs(host, "idmsa.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "appleid.cdn-apple.com")
	if(dnsDomainIs(host, "appleid.cdn-apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "appleid.apple.com")
	if(dnsDomainIs(host, "appleid.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "identity.ess.apple.com")
	if(dnsDomainIs(host, "identity.ess.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gsa.apple.com")
	if(dnsDomainIs(host, "gsa.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "iphone-ld.apple.com")
	if(dnsDomainIs(host, "iphone-ld.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "xp.apple.com")
	if(dnsDomainIs(host, "xp.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "api.apple-cloudkit.com")
	if(dnsDomainIs(host, "api.apple-cloudkit.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mesu.apple.com")
	if(dnsDomainIs(host, "mesu.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "siri.apple.com")
	if(dnsDomainIs(host, "siri.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "calendar.google.com")
	if(dnsDomainIs(host, "calendar.google.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*finance.yahoo.com*")
	if(shExpMatch(url, "*finance.yahoo.com*")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*apple-finance.query.yahoo.com*")
	if(shExpMatch(url, "*apple-finance.query.yahoo.com*")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "whatsapp.com")
	if(dnsDomainIs(host, "whatsapp.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "whatsapp.net")
	if(dnsDomainIs(host, "whatsapp.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "astorchocolate.com")
	if(dnsDomainIs(host, "astorchocolate.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.astorchocolate.com")
	if(shExpMatch(host, "*.astorchocolate.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "bergdorfgoodman.com")
	if(dnsDomainIs(host, "bergdorfgoodman.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.bergdorfgoodmanemail.com")
	if(shExpMatch(host, "*.bergdorfgoodmanemail.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.altbeacon.org")
	if(shExpMatch(host, "*.altbeacon.org")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "limosys.net")
	if(dnsDomainIs(host, "limosys.net")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.limosys.net")
	if(shExpMatch(host, "*.limosys.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "slack-msgs.com")
	if(dnsDomainIs(host, "slack-msgs.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "slack-edge.org")
	if(dnsDomainIs(host, "slack-edge.org")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.*.squareup.com")
	if(shExpMatch(host, "*.*.squareup.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.squareup.com")
	if(shExpMatch(host, "*.squareup.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "squareup.com")
	if(dnsDomainIs(host, "squareup.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "w-x.co")
	if(dnsDomainIs(host, "w-x.co")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "weather.com")
	if(dnsDomainIs(host, "weather.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "i.imwx.com")
	if(dnsDomainIs(host, "i.imwx.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "accu-weather.com")
	if(dnsDomainIs(host, "accu-weather.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "constantcontact.com")
	if(dnsDomainIs(host, "constantcontact.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "bankofamerica.com")
	if(dnsDomainIs(host, "bankofamerica.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "bac-assets.com")
	if(dnsDomainIs(host, "bac-assets.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mint.com")
	if(dnsDomainIs(host, "mint.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "pageonce.com")
	if(dnsDomainIs(host, "pageonce.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "intuit.com")
	if(dnsDomainIs(host, "intuit.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.intuit.com")
	if(shExpMatch(host, "*.intuit.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "check.me")
	if(dnsDomainIs(host, "check.me")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "wrike.com")
	if(dnsDomainIs(host, "wrike.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.wrike.com")
	if(shExpMatch(host, "*.wrike.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "macropinch.com")
	if(dnsDomainIs(host, "macropinch.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.macropinch.com")
	if(shExpMatch(host, "*.macropinch.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.gpsonextra.net")
	if(shExpMatch(host, "*.gpsonextra.net")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*kolhashiurim.com")
	if(shExpMatch(host, "*kolhashiurim.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*kolhalashon.com")
	if(shExpMatch(host, "*kolhalashon.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*lyft.com")
	if(shExpMatch(host, "*lyft.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*swiftkey.net")
	if(shExpMatch(host, "*swiftkey.net")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*swiftkey.com")
	if(shExpMatch(host, "*swiftkey.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.smartlistlocal.com")
	if(shExpMatch(host, "*.smartlistlocal.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "smartlistlocal.com")
	if(dnsDomainIs(host, "smartlistlocal.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.appioapp.com")
	if(shExpMatch(host, "*.appioapp.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.typography.com")
	if(shExpMatch(host, "*.typography.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.cuebiq.com")
	if(shExpMatch(host, "*.cuebiq.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*cuebiq.com")
	if(shExpMatch(host, "*cuebiq.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.usaepay.com")
	if(shExpMatch(host, "*.usaepay.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.textra.me")
	if(shExpMatch(host, "*.textra.me")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.wunderground.com")
	if(shExpMatch(host, "*.wunderground.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "limosys.com")
	if(dnsDomainIs(host, "limosys.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.limosys.com")
	if(shExpMatch(host, "*.limosys.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*weatherbug.com")
	if(shExpMatch(host, "*weatherbug.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.weatherbug.com")
	if(shExpMatch(host, "*.weatherbug.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*feeds.feedburner.com")
	if(shExpMatch(host, "*feeds.feedburner.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*mailchimp.com")
	if(shExpMatch(host, "*mailchimp.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.mailchimp.com")
	if(shExpMatch(host, "*.mailchimp.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*godaven.com")
	if(shExpMatch(host, "*godaven.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.thejapps.com")
	if(shExpMatch(host, "*.thejapps.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.lyftmail.com")
	if(shExpMatch(host, "*.lyftmail.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*office365.com")
	if(shExpMatch(host, "*office365.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*officeapps.live.com")
	if(shExpMatch(host, "*officeapps.live.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.office365.com")
	if(shExpMatch(host, "*.office365.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*spsoftmobile.com")
	if(shExpMatch(host, "*spsoftmobile.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.spsoftmobile.com")
	if(shExpMatch(host, "*.spsoftmobile.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "samsung-mobile.query.yahooapis.com")
	if(dnsDomainIs(host, "samsung-mobile.query.yahooapis.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "login.microsoftonline.com")
	if(dnsDomainIs(host, "login.microsoftonline.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.login.microsoftonline.com")
	if(shExpMatch(host, "*.login.microsoftonline.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "microsoftonline.com")
	if(dnsDomainIs(host, "microsoftonline.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "verizonwireless.com")
	if(dnsDomainIs(host, "verizonwireless.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.verizonwireless.com")
	if(shExpMatch(host, "*.verizonwireless.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*verizonwireless.com")
	if(shExpMatch(host, "*verizonwireless.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.vzw.com")
	if(shExpMatch(host, "*.vzw.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*caringhcny.org")
	if(shExpMatch(host, "*caringhcny.org")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "jcnmail.com")
	if(dnsDomainIs(host, "jcnmail.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.jcnmail.com")
	if(shExpMatch(host, "*.jcnmail.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "kosherrestaurantsgps.com")
	if(shExpMatch(host, "kosherrestaurantsgps.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "chabad.org")
	if(shExpMatch(host, "chabad.org")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "mychabad.org")
	if(shExpMatch(host, "mychabad.org")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "groupme.com")
	if(dnsDomainIs(host, "groupme.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "protonmail.com")
	if(dnsDomainIs(host, "protonmail.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "api.protonmail.ch")
	if(dnsDomainIs(host, "api.protonmail.ch")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "ubereats.com")
	if(dnsDomainIs(host, "ubereats.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*tdcardservices.com")
	if(shExpMatch(host, "*tdcardservices.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*tdbank.com")
	if(shExpMatch(host, "*tdbank.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.tdbank.com")
	if(shExpMatch(host, "*.tdbank.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.netxinvestor.com")
	if(shExpMatch(host, "*.netxinvestor.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*netxselect.com")
	if(shExpMatch(host, "*netxselect.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.tdsecurities.com")
	if(shExpMatch(host, "*.tdsecurities.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*centresuite.com")
	if(shExpMatch(host, "*centresuite.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*visaprepaidprocessing.com")
	if(shExpMatch(host, "*visaprepaidprocessing.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*clientpoint.fisglobal.com")
	if(shExpMatch(host, "*clientpoint.fisglobal.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*tdgroup.com")
	if(shExpMatch(host, "*tdgroup.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.tdgroup.com")
	if(shExpMatch(host, "*.tdgroup.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*mobileapptracking.com")
	if(shExpMatch(host, "*mobileapptracking.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.crashlytics.com")
	if(shExpMatch(host, "*.crashlytics.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*d1w2poirtb3as9.cloudfront.net")
	if(shExpMatch(host, "*d1w2poirtb3as9.cloudfront.net")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.geixahba.com")
	if(shExpMatch(host, "*.geixahba.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*geixahba.com")
	if(shExpMatch(host, "*geixahba.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.oojoovae.org")
	if(shExpMatch(host, "*.oojoovae.org")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*oojoovae.org")
	if(shExpMatch(host, "*oojoovae.org")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.shaipeeg.net")
	if(shExpMatch(host, "*.shaipeeg.net")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*shaipeeg.net")
	if(shExpMatch(host, "*shaipeeg.net")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.naevooda.co")
	if(shExpMatch(host, "*.naevooda.co")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*naevooda.co")
	if(shExpMatch(host, "*naevooda.co")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.ooshahwa.biz")
	if(shExpMatch(host, "*.ooshahwa.biz")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*ooshahwa.biz")
	if(shExpMatch(host, "*ooshahwa.biz")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.gimbal.com")
	if(shExpMatch(host, "*.gimbal.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*uber.com")
	if(shExpMatch(host, "*uber.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.uber.com")
	if(shExpMatch(host, "*.uber.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "d1w2poirtb3as9.cloudfront.net")
	if(dnsDomainIs(host, "d1w2poirtb3as9.cloudfront.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "weatherbug.com")
	if(dnsDomainIs(host, "weatherbug.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "1weather.onelouder.com")
	if(dnsDomainIs(host, "1weather.onelouder.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "nwsalert.onelouder.com")
	if(dnsDomainIs(host, "nwsalert.onelouder.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "skywisetiles.wdtinc.com")
	if(dnsDomainIs(host, "skywisetiles.wdtinc.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "1weather-quark.onelouder.com")
	if(dnsDomainIs(host, "1weather-quark.onelouder.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "discovercard.com")
	if(dnsDomainIs(host, "discovercard.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "discoverbank.com")
	if(dnsDomainIs(host, "discoverbank.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "d.aa.online-metrix.net")
	if(dnsDomainIs(host, "d.aa.online-metrix.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "discover.com")
	if(dnsDomainIs(host, "discover.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "online-metrix.net")
	if(dnsDomainIs(host, "online-metrix.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "liveperson.net")
	if(dnsDomainIs(host, "liveperson.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "jewishmusic.fm")
	if(dnsDomainIs(host, "jewishmusic.fm")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "nigunmusic.com")
	if(dnsDomainIs(host, "nigunmusic.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "lchaim.co.il")
	if(dnsDomainIs(host, "lchaim.co.il")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "lechaimmusic.com")
	if(dnsDomainIs(host, "lechaimmusic.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "myzmanim.com")
	if(dnsDomainIs(host, "myzmanim.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "boldleopard.com")
	if(dnsDomainIs(host, "boldleopard.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gonative.io")
	if(dnsDomainIs(host, "gonative.io")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "cdnjs.cloudflare.com")
	if(dnsDomainIs(host, "cdnjs.cloudflare.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "stackpath.bootstrapcdn.com")
	if(dnsDomainIs(host, "stackpath.bootstrapcdn.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "rebgershonribner.com")
	if(dnsDomainIs(host, "rebgershonribner.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*torahanytime.http.internapcdn.net")
	if(shExpMatch(host, "*torahanytime.http.internapcdn.net")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*files.torahanytime.com")
	if(shExpMatch(host, "*files.torahanytime.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*torahanytime.com")
	if(shExpMatch(host, "*torahanytime.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.vimeocdn.com")
	if(shExpMatch(host, "*.vimeocdn.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*vimeocdn.com")
	if(shExpMatch(host, "*vimeocdn.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*torahanytime.com")
	if(shExpMatch(host, "*torahanytime.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.fastly.net")
	if(shExpMatch(host, "*.fastly.net")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*fastly.net")
	if(shExpMatch(host, "*fastly.net")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*torahanytime-files.sfo2.digitaloceanspaces.com")
	if(shExpMatch(host, "*torahanytime-files.sfo2.digitaloceanspaces.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gcs-vimeo.akamaized.net")
	if(dnsDomainIs(host, "gcs-vimeo.akamaized.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "skyfiregce-vimeo.akamaized.net")
	if(dnsDomainIs(host, "skyfiregce-vimeo.akamaized.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "player.vimeo.com")
	if(dnsDomainIs(host, "player.vimeo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "akamaized.net")
	if(dnsDomainIs(host, "akamaized.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "outorah.org")
	if(dnsDomainIs(host, "outorah.org")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "dafyomi.co.il")
	if(dnsDomainIs(host, "dafyomi.co.il")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "ou.org")
	if(dnsDomainIs(host, "ou.org")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "zichru.com")
	if(dnsDomainIs(host, "zichru.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "sefaria.org")
	if(dnsDomainIs(host, "sefaria.org")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "zichru.com")
	if(dnsDomainIs(host, "zichru.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "jwplayer.com")
	if(shExpMatch(url, "jwplayer.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "jwpltx.com")
	if(shExpMatch(url, "jwpltx.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "videos-a.jwpsrv.com")
	if(shExpMatch(url, "videos-a.jwpsrv.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "public.boxcloud.com")
	if(shExpMatch(url, "public.boxcloud.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "res.cloudinary.com")
	if(dnsDomainIs(host, "res.cloudinary.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "alldaf.org")
	if(dnsDomainIs(host, "alldaf.org")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "dh6eybvt3x4p0.cloudfront.net")
	if(dnsDomainIs(host, "dh6eybvt3x4p0.cloudfront.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "buzzsprout.com")
	if(dnsDomainIs(host, "buzzsprout.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "content.jwplatform.com")
	if(dnsDomainIs(host, "content.jwplatform.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "ping-meta-prd.jwpltx.com")
	if(dnsDomainIs(host, "ping-meta-prd.jwpltx.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "entitlements.jwplayer.com")
	if(dnsDomainIs(host, "entitlements.jwplayer.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "ssl.p.jwpcdn.com")
	if(dnsDomainIs(host, "ssl.p.jwpcdn.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "prd.jwpltx.com")
	if(dnsDomainIs(host, "prd.jwpltx.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "public.boxcloud.com")
	if(dnsDomainIs(host, "public.boxcloud.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "lakewoodafyomi.appspot.com")
	if(dnsDomainIs(host, "lakewoodafyomi.appspot.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "media.ou.org")
	if(dnsDomainIs(host, "media.ou.org")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "lkwd-daf-yomi.nyc3.cdn.digitaloceanspaces.com")
	if(dnsDomainIs(host, "lkwd-daf-yomi.nyc3.cdn.digitaloceanspaces.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "videos-cloudflare.jwpsrv.com")
	if(dnsDomainIs(host, "videos-cloudflare.jwpsrv.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "videos-fms.jwpsrv.com")
	if(dnsDomainIs(host, "videos-fms.jwpsrv.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "assets-jpcust.jwpsrv.com")
	if(dnsDomainIs(host, "assets-jpcust.jwpsrv.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "firebaselogging-pa.googleapis.com")
	if(dnsDomainIs(host, "firebaselogging-pa.googleapis.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "dafhachaim.org")
	if(dnsDomainIs(host, "dafhachaim.org")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "swdaf.com")
	if(dnsDomainIs(host, "swdaf.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "swdaf.mamash.com")
	if(dnsDomainIs(host, "swdaf.mamash.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "outorah.auth0.com")
	if(dnsDomainIs(host, "outorah.auth0.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"clients3.google.com")
	if(dnsDomainIs(host,"clients3.google.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "allparsha.org")
	if(dnsDomainIs(host, "allparsha.org")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "sentry.oustatic.com")
	if(dnsDomainIs(host, "sentry.oustatic.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "parkmobileglobal.com")
	if(dnsDomainIs(host, "parkmobileglobal.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "parknyc.parkmobile.us")
	if(dnsDomainIs(host, "parknyc.parkmobile.us")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "parkmobile.us")
	if(dnsDomainIs(host, "parkmobile.us")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "parknyc.parkmobile.us")
	if(dnsDomainIs(host, "parknyc.parkmobile.us")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "secure.cardknox.com")
	if(dnsDomainIs(host, "secure.cardknox.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "cardknox.com")
	if(dnsDomainIs(host, "cardknox.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "xe.com")
	if(dnsDomainIs(host, "xe.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "tribalfusion.com")
	if(dnsDomainIs(host, "tribalfusion.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "statse.webtrendslive.com")
	if(dnsDomainIs(host, "statse.webtrendslive.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "fx2.xe.com")
	if(dnsDomainIs(host, "fx2.xe.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "smetrics.xe.com")
	if(dnsDomainIs(host, "smetrics.xe.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "tmi3.ios.xe.com")
	if(dnsDomainIs(host, "tmi3.ios.xe.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "car2go.com")
	if(dnsDomainIs(host, "car2go.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "csi.gstatic.com")
	if(dnsDomainIs(host, "csi.gstatic.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "geico.com")
	if(dnsDomainIs(host, "geico.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "americanexpress.com")
	if(dnsDomainIs(host, "americanexpress.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "online.americanexpress.com")
	if(dnsDomainIs(host, "online.americanexpress.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "so.americanexpress.com")
	if(dnsDomainIs(host, "so.americanexpress.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "business.americanexpress.com")
	if(dnsDomainIs(host, "business.americanexpress.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "travel.americanexpress.com")
	if(dnsDomainIs(host, "travel.americanexpress.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "amextravel.com")
	if(dnsDomainIs(host, "amextravel.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "travelspecialists.americanexpress.com")
	if(dnsDomainIs(host, "travelspecialists.americanexpress.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "travelinsiders.americanexpress.com")
	if(dnsDomainIs(host, "travelinsiders.americanexpress.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "amexglobalbusinesstravel.com")
	if(dnsDomainIs(host, "amexglobalbusinesstravel.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "network.americanexpress.com")
	if(dnsDomainIs(host, "network.americanexpress.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "compute-1.amazonaws.com")
	if(dnsDomainIs(host, "compute-1.amazonaws.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "ip4.stati.sl-reverse.com")
	if(dnsDomainIs(host, "ip4.stati.sl-reverse.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "americanexpress.com")
	if(dnsDomainIs(host, "americanexpress.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "capitalone.com")
	if(dnsDomainIs(host, "capitalone.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "capitaloneinvesting.com")
	if(dnsDomainIs(host, "capitaloneinvesting.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "bfp.capitalone.com")
	if(dnsDomainIs(host, "bfp.capitalone.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "verified.capitalone.com")
	if(dnsDomainIs(host, "verified.capitalone.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "capitaloneservices.tt.omtrdc.net")
	if(dnsDomainIs(host, "capitaloneservices.tt.omtrdc.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "secure.capitalone360.com")
	if(dnsDomainIs(host, "secure.capitalone360.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "smetrics.capitalone.com")
	if(dnsDomainIs(host, "smetrics.capitalone.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "cdn.tt.omtrdc.net")
	if(dnsDomainIs(host, "cdn.tt.omtrdc.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "login.capitalone.com")
	if(dnsDomainIs(host, "login.capitalone.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "login1.capitalone.com")
	if(dnsDomainIs(host, "login1.capitalone.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "dpm.demdex.net")
	if(dnsDomainIs(host, "dpm.demdex.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "capitalone.static.pub.247-inc.net")
	if(dnsDomainIs(host, "capitalone.static.pub.247-inc.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "capitalone.app.pub.247-inc.net")
	if(dnsDomainIs(host, "capitalone.app.pub.247-inc.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "deviceinfo.capitalone.com")
	if(dnsDomainIs(host, "deviceinfo.capitalone.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "capitalone.ca")
	if(dnsDomainIs(host, "capitalone.ca")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "capitaloneonline.co.uk")
	if(dnsDomainIs(host, "capitaloneonline.co.uk")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "totalsystemservices.d1.sc.omtrdc.net")
	if(dnsDomainIs(host, "totalsystemservices.d1.sc.omtrdc.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "content.capitaloneinvesting.com")
	if(dnsDomainIs(host, "content.capitaloneinvesting.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "home.capitalone360.com")
	if(dnsDomainIs(host, "home.capitalone360.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "paypal.com")
	if(dnsDomainIs(host, "paypal.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "paypal.112.2o7.net")
	if(dnsDomainIs(host, "paypal.112.2o7.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "paypalobjects.com")
	if(dnsDomainIs(host, "paypalobjects.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "paypalssl.doubleclick.net")
	if(dnsDomainIs(host, "paypalssl.doubleclick.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "citimobile.com")
	if(dnsDomainIs(host, "citimobile.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "citibankonline.com*")
	if(dnsDomainIs(host, "citibankonline.com*")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "citibank.com")
	if(dnsDomainIs(host, "citibank.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "web.da-us.citibank.com")
	if(dnsDomainIs(host, "web.da-us.citibank.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "citi.com")
	if(dnsDomainIs(host, "citi.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "myciti.com")
	if(dnsDomainIs(host, "myciti.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "citigroup.com")
	if(dnsDomainIs(host, "citigroup.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "citicards.com")
	if(dnsDomainIs(host, "citicards.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "accountonline.com")
	if(dnsDomainIs(host, "accountonline.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "citimortgage.com")
	if(dnsDomainIs(host, "citimortgage.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "online.citibank.com")
	if(dnsDomainIs(host, "online.citibank.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "online.citi.com")
	if(dnsDomainIs(host, "online.citi.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "citibusinessonline.com")
	if(dnsDomainIs(host, "citibusinessonline.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "citibankonline.com")
	if(dnsDomainIs(host, "citibankonline.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "businessaccess.citibank.citigroup.com")
	if(dnsDomainIs(host, "businessaccess.citibank.citigroup.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "citiretailservices.citibankonline.com")
	if(dnsDomainIs(host, "citiretailservices.citibankonline.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "robinhood.com")
	if(dnsDomainIs(host, "robinhood.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "app.adjust.com")
	if(dnsDomainIs(host, "app.adjust.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "api.branch.io")
	if(dnsDomainIs(host, "api.branch.io")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*brokerage-static.s*.amazonaws.com*")
	if(shExpMatch(url, "*brokerage-static.s*.amazonaws.com*")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*s*.amazonaws.com/brokerage-static*")
	if(shExpMatch(url, "*s*.amazonaws.com/brokerage-static*")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "robinhoodapp.zendesk.com")
	if(dnsDomainIs(host, "robinhoodapp.zendesk.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gojuno.com")
	if(dnsDomainIs(host, "gojuno.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "junosupport.zendesk.com")
	if(dnsDomainIs(host, "junosupport.zendesk.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*googleapis.com/userlocation*")
	if(shExpMatch(url, "*googleapis.com/userlocation*")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*google.com/glm/mmap*")
	if(shExpMatch(url, "*google.com/glm/mmap*")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*google.com/loc/m/api*")
	if(shExpMatch(url, "*google.com/loc/m/api*")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "maps.google.com")
	if(dnsDomainIs(host, "maps.google.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "branch.io")
	if(dnsDomainIs(host, "branch.io")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "leanplum.com")
	if(dnsDomainIs(host, "leanplum.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "*gojuno.onelink.me*")
	if(dnsDomainIs(host, "*gojuno.onelink.me*")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "app.artscroll.com")
	if(dnsDomainIs(host, "app.artscroll.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "artscroll.com")
	if(dnsDomainIs(host, "artscroll.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.artscroll.com")
	if(shExpMatch(host, "*.artscroll.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "secure.fidelipay.com")
	if(dnsDomainIs(host, "secure.fidelipay.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "fidelipay.com")
	if(dnsDomainIs(host, "fidelipay.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "*.fidelipay.com")
	if(shExpMatch(host, "*.fidelipay.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "santander.co.uk")
	if(dnsDomainIs(host, "santander.co.uk")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "santander.com")
	if(dnsDomainIs(host, "santander.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "metrics.santander.co.uk")
	if(dnsDomainIs(host, "metrics.santander.co.uk")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "service.maxymiser.net")
	if(dnsDomainIs(host, "service.maxymiser.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "business.santander.co.uk")
	if(dnsDomainIs(host, "business.santander.co.uk")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "retail.santander.co.uk")
	if(dnsDomainIs(host, "retail.santander.co.uk")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "m.santanderbank.com")
	if(dnsDomainIs(host, "m.santanderbank.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "santanderbank.com")
	if(dnsDomainIs(host, "santanderbank.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "entrust.net")
	if(dnsDomainIs(host, "entrust.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "santandercb.co.uk")
	if(dnsDomainIs(host, "santandercb.co.uk")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "apply.santanderbank.com")
	if(dnsDomainIs(host, "apply.santanderbank.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "kosherrestaurantsgps.com")
	if(dnsDomainIs(host, "kosherrestaurantsgps.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "koshersense.azurewebsites.net")
	if(dnsDomainIs(host, "koshersense.azurewebsites.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "hebcal.com")
	if(dnsDomainIs(host, "hebcal.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "janmadness.com")
	if(dnsDomainIs(host, "janmadness.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "torasavigdor.org")
	if(dnsDomainIs(host, "torasavigdor.org")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "torasavigdor.app")
	if(dnsDomainIs(host, "torasavigdor.app")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "wellsfargo.com")
	if(dnsDomainIs(host, "wellsfargo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "wellsfargomedia.com")
	if(dnsDomainIs(host, "wellsfargomedia.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "self-point.com")
	if(dnsDomainIs(host, "self-point.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "storage.googleapis.com")
	if(shExpMatch(host, "storage.googleapis.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "ecom.blob.core.windows.net")
	if(shExpMatch(host, "ecom.blob.core.windows.net")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "gonpgs.com")
	if(shExpMatch(host, "gonpgs.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "limebike.com")
	if(dnsDomainIs(host, "limebike.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "lime.biike")
	if(dnsDomainIs(host, "lime.biike")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "fitbit.com")
	if(dnsDomainIs(host, "fitbit.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "fitbitusercontent.com")
	if(dnsDomainIs(host, "fitbitusercontent.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "fitbitdevelopercontent.com")
	if(dnsDomainIs(host, "fitbitdevelopercontent.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "kolhalashon.com")
	if(dnsDomainIs(host, "kolhalashon.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "kolhashiurim.com")
	if(dnsDomainIs(host, "kolhashiurim.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "sefaria.org")
	if(dnsDomainIs(host, "sefaria.org")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "jewishbroadcast.com")
	if(dnsDomainIs(host, "jewishbroadcast.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "jewishmusicstream.com")
	if(dnsDomainIs(host, "jewishmusicstream.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "toker.fm")
	if(dnsDomainIs(host, "toker.fm")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "voscast.com")
	if(dnsDomainIs(host, "voscast.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "brochos.com")
	if(dnsDomainIs(host, "brochos.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "ndstream.net")
	if(dnsDomainIs(host, "ndstream.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "streamingpulse.info")
	if(dnsDomainIs(host, "streamingpulse.info")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "adpro.me")
	if(dnsDomainIs(host, "adpro.me")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "streamer.radio.co")
	if(dnsDomainIs(host, "streamer.radio.co")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "jstream.brochos.com")
	if(dnsDomainIs(host, "jstream.brochos.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "music.shira24.com")
	if(dnsDomainIs(host, "music.shira24.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "chemicalbank.com")
	if(dnsDomainIs(host, "chemicalbank.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mbanking-services.mobi")
	if(dnsDomainIs(host, "mbanking-services.mobi")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "huntington.com")
	if(dnsDomainIs(host, "huntington.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "tcfbank.com")
	if(dnsDomainIs(host, "tcfbank.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gourmetglattlakewood.com")
	if(dnsDomainIs(host, "gourmetglattlakewood.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gourmetglattmarket.com")
	if(dnsDomainIs(host, "gourmetglattmarket.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gourmetglattonline.com")
	if(dnsDomainIs(host, "gourmetglattonline.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "shira24.com")
	if(dnsDomainIs(host, "shira24.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "api.shira24.info")
	if(shExpMatch(host, "api.shira24.info")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "netgear.com")
	if(dnsDomainIs(host, "netgear.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "arlo.com")
	if(dnsDomainIs(host, "arlo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "stripe.com")
	if(dnsDomainIs(host, "stripe.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "stripe.network")
	if(dnsDomainIs(host, "stripe.network")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "visa.com")
	if(dnsDomainIs(host, "visa.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "checkout.visa.com")
	if(dnsDomainIs(host, "checkout.visa.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "visa3dsecure.com")
	if(dnsDomainIs(host, "visa3dsecure.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "authorize.net")
	if(dnsDomainIs(host, "authorize.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "masterpass.com")
	if(dnsDomainIs(host, "masterpass.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "postmates.com")
	if(dnsDomainIs(host, "postmates.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "instacart.com")
	if(dnsDomainIs(host, "instacart.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "instacart.ca")
	if(dnsDomainIs(host, "instacart.ca")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "starbucks.com")
	if(dnsDomainIs(host, "starbucks.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "starbucksrewards.com")
	if(dnsDomainIs(host, "starbucksrewards.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "engine.mobileapptracking.com")
	if(dnsDomainIs(host, "engine.mobileapptracking.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "starbucksassets.com")
	if(dnsDomainIs(host, "starbucksassets.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "7-eleven.com")
	if(dnsDomainIs(host, "7-eleven.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "coffeebeanrewards.com")
	if(dnsDomainIs(host, "coffeebeanrewards.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mobileandroidcbtl.punchh.com")
	if(dnsDomainIs(host, "mobileandroidcbtl.punchh.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "ordering.orders2.me")
	if(dnsDomainIs(host, "ordering.orders2.me")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "cdnstabletransit.com")
	if(dnsDomainIs(host, "cdnstabletransit.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mobileapphelper.com")
	if(dnsDomainIs(host, "mobileapphelper.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "analytics.lb.mobileapphelper.com")
	if(shExpMatch(url, "analytics.lb.mobileapphelper.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "orders2.me")
	if(shExpMatch(url, "orders2.me")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "ring.com")
	if(dnsDomainIs(host, "ring.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "prd.rings.solutions")
	if(dnsDomainIs(host, "prd.rings.solutions")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "api.ring.com")
	if(dnsDomainIs(host, "api.ring.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "ajax.aspnetcdn.com")
	if(dnsDomainIs(host, "ajax.aspnetcdn.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "firstrepublic.com")
	if(dnsDomainIs(host, "firstrepublic.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "usbank.com")
	if(dnsDomainIs(host, "usbank.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "usbpayment.com")
	if(dnsDomainIs(host, "usbpayment.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "fleetcommanderonline.com")
	if(dnsDomainIs(host, "fleetcommanderonline.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "checkfree.com")
	if(dnsDomainIs(host, "checkfree.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "bankofthewest.com")
	if(dnsDomainIs(host, "bankofthewest.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "*amazon.com:443/wholefoodsapp*")
	if(shExpMatch(url, "*amazon.com:443/wholefoodsapp*")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "cash.me")
	if(dnsDomainIs(host, "cash.me")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "squarecdn.com")
	if(dnsDomainIs(host, "squarecdn.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "bankofcavecity.com")
	if(dnsDomainIs(host, "bankofcavecity.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "cashedge.com")
	if(dnsDomainIs(host, "cashedge.com")) return "DIRECT";

	//FROM RULE: PROXY:true
	if(true) return "PROXY gtnpios.gentechsolution.com:50100;";

}
