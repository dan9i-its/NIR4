from django.db import models
from django.contrib.auth.models import User

class FullScan(models.Model):
    status = models.CharField('Статус полного скана', max_length=50,default='Новый')
    domains = models.TextField('Домены')
    time_start = models.TimeField(auto_now=True,null=True)
    time_end = models.TimeField(auto_now=True, null=True)
    def __str__(self):
        return str(self.time_start)
    
    class Meta:
        verbose_name = 'Скан'
        verbose_name_plural = 'Сканы'

class NucleiScan(models.Model):
    domain = models.CharField('Домен', max_length=250)
    status = models.CharField('Статус скана Nuclei', max_length=150)
    full_scan = models.ForeignKey(FullScan, on_delete=models.CASCADE)

    class Meta:
        verbose_name = 'Nuclei скан'
        verbose_name_plural = 'Сканы nuclei'
    def __str__(self):
        return str(self.domain)



class CrawlScan(models.Model):
    domain = models.CharField('Домен', max_length=250)
    status = models.CharField('Статус краулинга', max_length=150)
    full_scan = models.ForeignKey(FullScan, on_delete=models.CASCADE)
    class Meta:
        verbose_name = 'Crawl скан'
        verbose_name_plural = 'Сканы краулеров'
    def __str__(self):
        return str(self.domain)

class Har(models.Model):
    CrawlScan = models.ForeignKey(CrawlScan, on_delete=models.CASCADE)
    har = models.TextField('Запрос',default=' ')
    domain = models.CharField('Домен', max_length=250,default=' ')
    status = models.CharField('Cтатус', max_length=250,default=' ')
    type = models.CharField('Тип', max_length=250,default='Пасивный')
    class Meta:
        verbose_name = 'HAR'
        verbose_name_plural = 'HARs'
    def __str__(self):
        return str(self.domain)
    
class ZapScan(models.Model):
    full_scan = models.ForeignKey(FullScan, on_delete=models.CASCADE)
    har_id = models.ForeignKey(Har, on_delete=models.CASCADE)
    status = models.CharField('Статус', max_length=50,default='Новый')
    class Meta:
        verbose_name = 'Zap Scan'
        verbose_name_plural = 'Zap Scans'
    def __str__(self):
        return str(self.id)


class Comment(models.Model):
    User = models.ForeignKey(User, on_delete=models.CASCADE)
    comment = models.TextField('Комментарий', default=' ', null=True)
    time = models.TimeField(auto_now=True,null=True)
    class Meta:
        verbose_name = 'Комментарий'
        verbose_name_plural = 'Комментарии'
    def __str__(self):
        return str(self.id)

class ZapTrigger(models.Model):
    Zap_scan = models.ForeignKey(ZapScan, on_delete=models.CASCADE)
    har_id = models.ForeignKey(Har, on_delete=models.CASCADE)
    comment = models.ForeignKey(Comment, on_delete=models.CASCADE, null=True)
    rule = models.TextField('Правило',default=' ')
    riskdesc = models.TextField('Уровень',default='информативный')
    instance_metod = models.TextField('Метод',default='GET')
    instance_param = models.TextField('Параметры',default=' ')
    instance_attack= models.TextField('Атака',default=' ')
    instance_evidence = models.TextField('PoC',default=' ')
    instance_url = models.TextField('URL',default=' ')
    instance_otherinfo = models.TextField('Доп информация',default=' ')
    status = models.CharField('Статус', max_length=50,default='Новый')
   #comment=models.TextField('Комментарий', default=' ', null=True)
    description = models.TextField('Описание',default=' ')
    class Meta:
        verbose_name = 'Срабатывание ZAP'
        verbose_name_plural = 'Срабатывания ZAP'
    def __str__(self):
        return str(self.id)



class NucleiTrigger(models.Model):
    NucleiScan = models.ForeignKey(NucleiScan, on_delete=models.CASCADE)
    comment = models.ForeignKey(Comment, on_delete=models.CASCADE, null=True)
    rule = models.TextField('Правило',default=' ')
    description = models.TextField('Описание',default=' ')
    status = models.CharField('Статус триажа', max_length=150,default=' ')
    severity = models.CharField('Критичность', max_length=50,default=' ')
    domain = models.CharField('Домен', max_length=250,default=' ')

    class Meta:
        verbose_name = 'Срабатывание nuclei'
        verbose_name_plural = 'Срабатывания nuclei'

    def __str__(self):
        return str(self.domain)
    

class ProxyConfig(models.Model):
    Scan = models.ForeignKey(FullScan, on_delete=models.CASCADE)
    IP = models.TextField('IP',default=' ')
    port = models.TextField('port',default=' ')
    logins = models.TextField('Логины', max_length=1000000000,default=' ')
    passwords = models.TextField('Пароли', max_length=100000000,default=' ')
    key = models.TextField('Ключ подписиси jwt', max_length=250,default=' ')
    expiretime = models.TextField('Время жизни в секундах', max_length=100,default=' ')
    csrf_name = models.TextField('csrf token name', max_length=100,default=' ')
    csrf_param_name = models.TextField('csrf param name', max_length=100,default=' ')
    auth_token_type = models.TextField('auth token type', max_length=100,default=' ')
    auth_token_name = models.TextField('auth token name', max_length=100,default=' ')
    auth_type = models.TextField('auth type', max_length=100,default=' ')
    token_refresh_end = models.TextField('token refresh end', max_length=100,default=' ')
    status = models.TextField('status', max_length=100,default='stopped')
    auth_request = models.TextField('auth request', max_length=100000,default=' ')
    request_to_csrf = models.TextField('auth request', max_length=100000,default=' ')
    login_name = models.TextField('login param name', max_length=100000,default=' ')
    password_name = models.TextField('password param name', max_length=100000,default=' ')
    period_status = models.TextField('period status', max_length=100000,default=' ')
    
    class Meta:
        verbose_name = 'Proxy config'
        verbose_name_plural = 'Proxy configs'

    def __str__(self):
        return str(self.IP)
