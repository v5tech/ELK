# ELK

搭建ELK日志分析平台。此处为其核心配置文件。具体搭建过程请参考[ELK环境搭建.docx](https://raw.githubusercontent.com/sxyx2008/ELK/master/ELK环境搭建.docx "ELK环境搭建.docx")文档

环境:

```
Vagrant 1.8.1
CentOS 7.2 192.168.0.228
Elasticsearch 2.3.2
logstash 2.2.4
Kibana 4.4.2
filebeat 1.2.2
topbeat 1.2.2
```

# Screenshots

Nginx日志分析

![](https://raw.githubusercontent.com/sxyx2008/ELK/master/Screenshots/Discover-Kibana-Nginx.png)

Syslog系统日志分析

![](https://raw.githubusercontent.com/sxyx2008/ELK/master/Screenshots/Discover-Kibana-Syslog.png)

Tomcat日志分析

![](https://raw.githubusercontent.com/sxyx2008/ELK/master/Screenshots/Discover-Kibana-Tomcat.png)

系统日志分析

![](https://raw.githubusercontent.com/sxyx2008/ELK/master/Screenshots/Discover-Kibana-Topbeat.png)

Topbeat Dashboard

![](https://raw.githubusercontent.com/sxyx2008/ELK/master/Screenshots/Topbeat-Dashboard-Kibana.png)



# 参考文章

https://www.digitalocean.com/community/tutorials/how-to-install-elasticsearch-logstash-and-kibana-elk-stack-on-centos-7

https://www.digitalocean.com/community/tutorials/how-to-gather-infrastructure-metrics-with-topbeat-and-elk-on-centos-7

https://www.digitalocean.com/community/tutorials/adding-logstash-filters-to-improve-centralized-logging

https://www.digitalocean.com/community/tutorials/how-to-use-kibana-dashboards-and-visualizations

https://www.digitalocean.com/community/tutorials/how-to-map-user-location-with-geoip-and-elk-elasticsearch-logstash-and-kibana


# tomcat日志分析参考

https://github.com/sdd330/tomcat-elk

http://blog.kazaff.me/2015/06/05/日志收集架构--ELK/

https://aggarwalarpit.wordpress.com/2015/12/03/configuring-elk-stack-to-analyse-apache-tomcat-logs/

https://www.systemcodegeeks.com/web-servers/apache/configuring-elk-stack-analyse-apache-tomcat-logs/

http://stackoverflow.com/questions/25429377/how-can-i-integrate-tomcat6s-catalina-out-file-with-logstash-elasticsearch

https://blog.codecentric.de/en/2014/10/log-management-spring-boot-applications-logstash-elastichsearch-kibana/

https://blog.lanyonm.org/articles/2014/01/12/logstash-multiline-tomcat-log-parsing.html

https://spredzy.wordpress.com/2013/03/02/monitor-your-cluster-of-tomcat-applications-with-logstash-and-kibana/



# yml语法校验

http://yaml-online-parser.appspot.com/

http://www.yamllint.com/


# linux平台系统运维教程集

https://www.digitalocean.com/community/tutorials

http://www.unixmen.com/

http://linoxide.com/
