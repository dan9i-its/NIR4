from django.contrib import admin
from .models import FullScan,NucleiScan, NucleiTrigger, CrawlScan, Har, ZapScan, ZapTrigger, Comment, ProxyConfig

admin.site.register(FullScan)
admin.site.register(NucleiScan)
admin.site.register(NucleiTrigger)
admin.site.register(CrawlScan)
admin.site.register(Har)
admin.site.register(ZapTrigger)
admin.site.register(ZapScan)
#admin.site.register(User)
admin.site.register(Comment)
admin.site.register(ProxyConfig)