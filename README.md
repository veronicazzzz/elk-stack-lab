# elk-stack-lab
Выполнили: Завьялова, Казачкова, Ким

Заранее были настроены 2 VPS: 

`proxy: 128.199.229.53`

`elk: 188.166.182.161`

## Squid
### Установка и настройка
Выполняем следующие шаги на менее мощном VPS (сервер proxy)
```
sudo apt update
sudo apt install squid
```
Затем необходимо изменить файл конфига Squid
```
sudo nano /etc/squid/squid.conf
```
В файле конфига после `include /etc/squid/conf.d/*` необхомо добавить следующие строчки: 
1. `auth_param basic program /usr/lib/squid3/basic_ncsa_auth /etc/squid/passwords`
2. `auth_param basic realm proxy`
3. `acl authenticated proxy_auth REQUIRED`
4. `acl localnet src *ip адрес локальной машины*`
5. `http_access allow authenticated`

## Apache
### Установка и запуск сервера 
```
sudo apt install apache2-utils
sudo htpasswd -c /etc/squid/passwords *squid_username*
```
Затем запускаем Squid
```
sudo systemctl start squid
sudo systemctl enable squid
sudo ufw allow 3128
```
Проверим работоспособожность proxy при помощи curl
```
sudo curl -v -x http://__squid_username__:__squid_password__@ip:3128 http://linkedin.com
```

Также для проверки работоспособности можно подключиться к прокси с локальной машины:

![изображение](https://user-images.githubusercontent.com/63861460/166237702-e532d7f2-1a51-4d85-9cfa-637c296ca763.png)

![изображение](https://user-images.githubusercontent.com/63861460/166237595-a468178e-f3ce-4e6c-a0f2-3134efefdb15.png)

## Elasticsearch
### Установка и настройка
Теперь работаем с более мощным VPS (необходимо 8Гб оперативной памяти)
Для работы Elasticsearch необходима установка Java
```properties
sudo apt update
sudo apt install default-jre
sudo apt install default-jdk
```
Поскольку Elasticsearch отсутствуетт в apt, необходимо получить открытый ключ Elasticsearch GPG
```
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
```
Затем в `source.list.d` необходимо добавить список источников Elasticsearch
```
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-7.x.list
```
Далее обновляем список пакетов apt и устанавливаем Elasticsearch
```
sudo apt update
sudo apt install elasticsearch
```
Открываем файл конфига Elasticsearch 
```
sudo nano /etc/elasticsearch/elasticsearch.yml
```
Добавляем в него следующие строчки: 
1. `network.host: 0.0.0.0`
2. `discovery.type: single-node`
3. `xpack.security.enabled: true`

Запускаем Elasticsearch
```
sudo systemctl start elasticsearch
sudo systemctl enable elasticsearch
```
Создаем пользователей 
```
sudo -u root /usr/share/elasticsearch/bin/elasticsearch-setup-passwords auto
```
Вывод необходимо сохранить, поскольку пароли понадобятся позже

## Kibana
### Установка и настройка 
```
sudo apt install kibana
```
Необходимо изменить файл конфига Kibana 
```
sudo nano /etc/kibana/kibana.yml
```
Изменяем следующие строчки:
1. `server.port: 5601`
2. `server.host: "0.0.0.0"`
3. `elasticsearch.hosts: ["http://0.0.0.0:9200"]`
4. `elasticsearch.username: "kibana_system"`

Запускаем Kibana
```
sudo systemctl start kibana
sudo systemctl enable kibana
```
Затем необходимо добавить пароль
```
sudo -u root /usr/share/kibana/bin/kibana-keystore create
sudo -u root /usr/share/kibana/bin/kibana-keystore add elasticsearch.password
```
Вписываем пароль, который получили ранее (для kibana_system)

## Logstash
### Установка и настройка
```
sudo apt install logstash
```
Затем необходимо изменить файл конфига `logstash.conf`
```
sudo nano /etc/logstash/conf.d/logstash.conf
```
Вписываем следующее (пока без фильтров grok)
```properties
input { 
    beats { 
        port => 5044 
    }
}

filter {

}

output {
  elasticsearch {
    hosts => ["*elk_ip*:9200"]
    manage_template => false 
    index => "%{[@metadata][beat]}-%{[@metadata[version]}-%{+YYYY.MM.dd}"
    user => "*elk_username*"
    password => "*elk_password*"
  }
}

```
Проверяем синтаксис конфига
```
sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t
```
Запускаем Logstash
```
sudo systemctl start logstash
sudo systemctl enable logstash
```
### Filebeat
## Установка и настройка 
Снова переходим к прокси серверу
```
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-7.x.list
sudo apt install filebeat
```
Настраиваем файл конфига для Filebeat
```
sudo filebeat modules enable system
sudo nano /etc/filebeat/filebeat.yml
```
1. строчки `output.elasticsearch` и `hosts: ["localhost:9200"]` комментируем
2. строчки `output.logstash` и `hosts: ["localhost:5044"]` раскомментируем, `localhost` изменяем на IP-адрес ELK-сервера

Проверяем конфиг
```
sudo filebeat -e test output
```
Затем вводим следующие команды
```
sudo filebeat setup --pipelines --modules system
sudo filebeat setup --index-management -E output.logstash.enabled=false -E 'output.elasticsearch.hosts=["__ELK_IP__:9200"]' -E 'output.elasticsearch.username="elastic"' -E 'output.elasticsearch.password="__elasticpassword__"'
sudo filebeat setup --index-management -E output.logstash.enabled=false -E 'output.elasticsearch.hosts=["__ELK_IP__:9200"]' -E 'output.elasticsearch.username="elastic"' -E 'output.elasticsearch.password="__elasticpassword__"' -E setup.kibana.host=__ELK_IP__:5601
```
Запускаем Filebeat
```
sudo systemctl start filebeat
sudo systemctl enable filebeat
curl -u _username_:_password -XGET 'http://_elk_ip_:9200/filebeat-*/_search?pretty'
```

## Правила GROK

### 1. src & dist ip
#### message
```
Apr 29 07:47:40 proxy-sing kernel: [ 5192.614872] [UFW BLOCK] IN=eth0 OUT= MAC=4a:cf:4c:3f:21:bb:fe:00:00:00:01:01:08:00 SRC=198.144.159.105 DST=128.199.229.53 LEN=40 TOS=0x08 PREC=0x00 TTL=233 ID=47590 PROTO=TCP SPT=57960 DPT=2440 WINDOW=1024 RES=0x00 SYN URGP=0
```
#### filter
```
"%{SYSLOGTIMESTAMP} %{DATA:server_name} %{WORD:service}: \[%{DATA}\] \[UFW BLOCK] IN=%{WORD:in} OUT=%{GREEDYDATA} MAC=%{GREEDYDATA:mac} SRC=%{IP:src_ip} DST=%{IP:dst_ip}"
```
#### json
```
{
  "_index": "filebeat-7.17.3-2022.04.29",
  "_type": "_doc",
  "_id": "3Or8dIABSkcyO0_gqdGP",
  "_version": 1,
  "_score": 1,
  "_source": {
    "in": "eth0",
    "src_ip": "45.155.205.99",
    "ecs": {
      "version": "1.12.0"
    },
    "server_name": "proxy-sing",
    "service": {
      "type": "system"
    },
    "@timestamp": "2022-04-29T11:02:36.084Z",
    "input": {
      "type": "log"
    },
    "cloud": {
      "service": {
        "name": "Droplets"
      },
      "instance": {
        "id": "297628093"
      },
      "region": "sgp1",
      "provider": "digitalocean"
    },
    "log": {
      "file": {
        "path": "/var/log/syslog"
      },
      "offset": 934454
    },
    "fileset": {
      "name": "syslog"
    },
    "mac": "4a:cf:4c:3f:21:bb:fe:00:00:00:01:01:08:00",
    "agent": {
      "ephemeral_id": "ce7a72e4-5321-48db-ad74-d9be2f47ab0a",
      "version": "7.17.3",
      "id": "913c66a2-6afc-4579-9ad6-a1e9b1805dae",
      "name": "proxy-sing",
      "hostname": "proxy-sing",
      "type": "filebeat"
    },
    "dst_ip": "128.199.229.53",
    "@version": "1",
    "host": {
      "ip": [
        "128.199.229.53",
        "10.15.0.5",
        "fe80::48cf:4cff:fe3f:21bb",
        "10.104.0.2",
        "fe80::c02a:a8ff:fe14:c561"
      ],
      "id": "87d83c1a544b6a958acd6c2f626b83fc",
      "hostname": "proxy-sing",
      "name": "proxy-sing",
      "architecture": "x86_64",
      "os": {
        "version": "20.04.4 LTS (Focal Fossa)",
        "family": "debian",
        "kernel": "5.4.0-107-generic",
        "name": "Ubuntu",
        "codename": "focal",
        "type": "linux",
        "platform": "ubuntu"
      },
      "mac": [
        "4a:cf:4c:3f:21:bb",
        "c2:2a:a8:14:c5:61"
      ],
      "containerized": false
    },
    "tags": [
      "beats_input_codec_plain_applied"
    ],
    "event": {
      "module": "system",
      "timezone": "+00:00",
      "dataset": "system.syslog"
    }
  },
  "fields": {
    "server_name": [
      "proxy-sing"
    ],
    "host.os.name.text": [
      "Ubuntu"
    ],
    "host.hostname": [
      "proxy-sing"
    ],
    "host.mac": [
      "4a:cf:4c:3f:21:bb",
      "c2:2a:a8:14:c5:61"
    ],
    "mac": [
      "4a:cf:4c:3f:21:bb:fe:00:00:00:01:01:08:00"
    ],
    "dst_ip": [
      "128.199.229.53"
    ],
    "src_ip": [
      "45.155.205.99"
    ],
    "service.type": [
      "system"
    ],
    "host.ip": [
      "128.199.229.53",
      "10.15.0.5",
      "fe80::48cf:4cff:fe3f:21bb",
      "10.104.0.2",
      "fe80::c02a:a8ff:fe14:c561"
    ],
    "cloud.instance.id": [
      "297628093"
    ],
    "agent.type": [
      "filebeat"
    ],
    "event.module": [
      "system"
    ],
    "host.os.version": [
      "20.04.4 LTS (Focal Fossa)"
    ],
    "host.os.kernel": [
      "5.4.0-107-generic"
    ],
    "@version": [
      "1"
    ],
    "host.os.name": [
      "Ubuntu"
    ],
    "agent.name": [
      "proxy-sing"
    ],
    "host.name": [
      "proxy-sing"
    ],
    "host.id": [
      "87d83c1a544b6a958acd6c2f626b83fc"
    ],
    "event.timezone": [
      "+00:00"
    ],
    "host.os.type": [
      "linux"
    ],
    "cloud.region": [
      "sgp1"
    ],
    "in": [
      "eth0"
    ],
    "fileset.name": [
      "syslog"
    ],
    "host.os.codename": [
      "focal"
    ],
    "input.type": [
      "log"
    ],
    "log.offset": [
      934454
    ],
    "agent.hostname": [
      "proxy-sing"
    ],
    "tags": [
      "beats_input_codec_plain_applied"
    ],
    "host.architecture": [
      "x86_64"
    ],
    "cloud.provider": [
      "digitalocean"
    ],
    "@timestamp": [
      "2022-04-29T11:02:36.084Z"
    ],
    "agent.id": [
      "913c66a2-6afc-4579-9ad6-a1e9b1805dae"
    ],
    "cloud.service.name": [
      "Droplets"
    ],
    "ecs.version": [
      "1.12.0"
    ],
    "host.containerized": [
      false
    ],
    "host.os.platform": [
      "ubuntu"
    ],
    "log.file.path": [
      "/var/log/syslog"
    ],
    "agent.ephemeral_id": [
      "ce7a72e4-5321-48db-ad74-d9be2f47ab0a"
    ],
    "agent.version": [
      "7.17.3"
    ],
    "host.os.family": [
      "debian"
    ],
    "event.dataset": [
      "system.syslog"
    ]
  }
}
```
### 2. ssh
#### message
```
Apr 29 10:05:26 proxy-sing sshd[5088]: Accepted password for nika from 213.59.143.74 port 49442 ssh2
```
#### filter
```
"%{SYSLOGTIMESTAMP} %{DATA:server_name} sshd\[%{NUMBER}\]: %{DATA:status} for %{WORD:user_name} from %{IP:src_ip} port %{NUMBER:port}"
```
#### json
```
{
  "_index": "filebeat-7.17.3-2022.04.29",
  "_type": "_doc",
  "_id": "c-rwdIABSkcyO0_gH9GH",
  "_version": 4,
  "_score": 1,
  "_source": {
    "ecs": {
      "version": "1.12.0"
    },
    "cloud": {
      "provider": "digitalocean",
      "region": "sgp1",
      "service": {
        "name": "Droplets"
      },
      "instance": {
        "id": "297628093"
      }
    },
    "service": {
      "type": "system"
    },
    "event": {
      "timezone": "+00:00",
      "module": "system",
      "dataset": "system.auth"
    },
    "src_ip": "213.59.143.74",
    "input": {
      "type": "log"
    },
    "server_name": "proxy-sing",
    "tags": [
      "beats_input_codec_plain_applied"
    ],
    "user_name": "nika",
    "@version": "1",
    "log": {
      "file": {
        "path": "/var/log/auth.log"
      },
      "offset": 25637
    },
    "port": "58408",
    "@timestamp": "2022-04-29T10:48:54.315Z",
    "agent": {
      "version": "7.17.3",
      "id": "913c66a2-6afc-4579-9ad6-a1e9b1805dae",
      "ephemeral_id": "ce7a72e4-5321-48db-ad74-d9be2f47ab0a",
      "name": "proxy-sing",
      "hostname": "proxy-sing",
      "type": "filebeat"
    },
    "fileset": {
      "name": "auth"
    },
    "status": "Accepted password",
    "host": {
      "os": {
        "codename": "focal",
        "version": "20.04.4 LTS (Focal Fossa)",
        "family": "debian",
        "name": "Ubuntu",
        "kernel": "5.4.0-107-generic",
        "type": "linux",
        "platform": "ubuntu"
      },
      "id": "87d83c1a544b6a958acd6c2f626b83fc",
      "ip": [
        "128.199.229.53",
        "10.15.0.5",
        "fe80::48cf:4cff:fe3f:21bb",
        "10.104.0.2",
        "fe80::c02a:a8ff:fe14:c561"
      ],
      "name": "proxy-sing",
      "hostname": "proxy-sing",
      "containerized": false,
      "architecture": "x86_64",
      "mac": [
        "4a:cf:4c:3f:21:bb",
        "c2:2a:a8:14:c5:61"
      ]
    }
  },
  "fields": {
    "server_name": [
      "proxy-sing"
    ],
    "host.os.name.text": [
      "Ubuntu"
    ],
    "user_name": [
      "nika"
    ],
    "host.hostname": [
      "proxy-sing"
    ],
    "host.mac": [
      "4a:cf:4c:3f:21:bb",
      "c2:2a:a8:14:c5:61"
    ],
    "src_ip": [
      "213.59.143.74"
    ],
    "service.type": [
      "system"
    ],
    "host.ip": [
      "128.199.229.53",
      "10.15.0.5",
      "fe80::48cf:4cff:fe3f:21bb",
      "10.104.0.2",
      "fe80::c02a:a8ff:fe14:c561"
    ],
    "cloud.instance.id": [
      "297628093"
    ],
    "agent.type": [
      "filebeat"
    ],
    "event.module": [
      "system"
    ],
    "host.os.version": [
      "20.04.4 LTS (Focal Fossa)"
    ],
    "host.os.kernel": [
      "5.4.0-107-generic"
    ],
    "@version": [
      "1"
    ],
    "host.os.name": [
      "Ubuntu"
    ],
    "agent.name": [
      "proxy-sing"
    ],
    "host.name": [
      "proxy-sing"
    ],
    "host.id": [
      "87d83c1a544b6a958acd6c2f626b83fc"
    ],
    "event.timezone": [
      "+00:00"
    ],
    "host.os.type": [
      "linux"
    ],
    "cloud.region": [
      "sgp1"
    ],
    "fileset.name": [
      "auth"
    ],
    "host.os.codename": [
      "focal"
    ],
    "input.type": [
      "log"
    ],
    "log.offset": [
      25637
    ],
    "agent.hostname": [
      "proxy-sing"
    ],
    "tags": [
      "beats_input_codec_plain_applied"
    ],
    "host.architecture": [
      "x86_64"
    ],
    "cloud.provider": [
      "digitalocean"
    ],
    "@timestamp": [
      "2022-04-29T10:48:54.315Z"
    ],
    "agent.id": [
      "913c66a2-6afc-4579-9ad6-a1e9b1805dae"
    ],
    "cloud.service.name": [
      "Droplets"
    ],
    "port": [
      "58408"
    ],
    "ecs.version": [
      "1.12.0"
    ],
    "host.containerized": [
      false
    ],
    "host.os.platform": [
      "ubuntu"
    ],
    "log.file.path": [
      "/var/log/auth.log"
    ],
    "agent.ephemeral_id": [
      "ce7a72e4-5321-48db-ad74-d9be2f47ab0a"
    ],
    "agent.version": [
      "7.17.3"
    ],
    "host.os.family": [
      "debian"
    ],
    "event.dataset": [
      "system.auth"
    ],
    "status": [
      "Accepted password"
    ]
  }
}
```
### 3. sudo
#### message
```
Apr 29 08:12:54 proxy-sing sudo:     nika : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/nano /etc/squid/conf.d/squid.conf
```
#### filter
```
"%{SYSLOGTIMESTAMP} %{DATA:server_name} sudo: %{DATA:user_name}: %{GREEDYDATA} ; COMMAND=%{GREEDYDATA:command}"
```
#### json
```
{
  "_index": "filebeat-7.17.3-2022.04.29",
  "_type": "_doc",
  "_id": "rur0dIABSkcyO0_gs9GB",
  "_version": 1,
  "_score": 1,
  "_source": {
    "ecs": {
      "version": "1.12.0"
    },
    "server_name": "proxy-sing",
    "@timestamp": "2022-04-29T10:53:54.331Z",
    "service": {
      "type": "system"
    },
    "input": {
      "type": "log"
    },
    "cloud": {
      "region": "sgp1",
      "instance": {
        "id": "297628093"
      },
      "provider": "digitalocean",
      "service": {
        "name": "Droplets"
      }
    },
    "log": {
      "file": {
        "path": "/var/log/auth.log"
      },
      "offset": 26221
    },
    "fileset": {
      "name": "auth"
    },
    "user_name": "    nika ",
    "command": "/usr/bin/nano test.log",
    "agent": {
      "version": "7.17.3",
      "ephemeral_id": "ce7a72e4-5321-48db-ad74-d9be2f47ab0a",
      "id": "913c66a2-6afc-4579-9ad6-a1e9b1805dae",
      "name": "proxy-sing",
      "hostname": "proxy-sing",
      "type": "filebeat"
    },
    "@version": "1",
    "host": {
      "ip": [
        "128.199.229.53",
        "10.15.0.5",
        "fe80::48cf:4cff:fe3f:21bb",
        "10.104.0.2",
        "fe80::c02a:a8ff:fe14:c561"
      ],
      "id": "87d83c1a544b6a958acd6c2f626b83fc",
      "name": "proxy-sing",
      "hostname": "proxy-sing",
      "architecture": "x86_64",
      "os": {
        "version": "20.04.4 LTS (Focal Fossa)",
        "family": "debian",
        "kernel": "5.4.0-107-generic",
        "name": "Ubuntu",
        "codename": "focal",
        "type": "linux",
        "platform": "ubuntu"
      },
      "mac": [
        "4a:cf:4c:3f:21:bb",
        "c2:2a:a8:14:c5:61"
      ],
      "containerized": false
    },
    "tags": [
      "beats_input_codec_plain_applied"
    ],
    "event": {
      "module": "system",
      "timezone": "+00:00",
      "dataset": "system.auth"
    }
  },
  "fields": {
    "server_name": [
      "proxy-sing"
    ],
    "host.os.name.text": [
      "Ubuntu"
    ],
    "user_name": [
      "    nika "
    ],
    "host.hostname": [
      "proxy-sing"
    ],
    "host.mac": [
      "4a:cf:4c:3f:21:bb",
      "c2:2a:a8:14:c5:61"
    ],
    "service.type": [
      "system"
    ],
    "host.ip": [
      "128.199.229.53",
      "10.15.0.5",
      "fe80::48cf:4cff:fe3f:21bb",
      "10.104.0.2",
      "fe80::c02a:a8ff:fe14:c561"
    ],
    "cloud.instance.id": [
      "297628093"
    ],
    "agent.type": [
      "filebeat"
    ],
    "event.module": [
      "system"
    ],
    "host.os.version": [
      "20.04.4 LTS (Focal Fossa)"
    ],
    "host.os.kernel": [
      "5.4.0-107-generic"
    ],
    "@version": [
      "1"
    ],
    "host.os.name": [
      "Ubuntu"
    ],
    "agent.name": [
      "proxy-sing"
    ],
    "host.name": [
      "proxy-sing"
    ],
    "host.id": [
      "87d83c1a544b6a958acd6c2f626b83fc"
    ],
    "event.timezone": [
      "+00:00"
    ],
    "host.os.type": [
      "linux"
    ],
    "cloud.region": [
      "sgp1"
    ],
    "fileset.name": [
      "auth"
    ],
    "host.os.codename": [
      "focal"
    ],
    "input.type": [
      "log"
    ],
    "log.offset": [
      26221
    ],
    "agent.hostname": [
      "proxy-sing"
    ],
    "command": [
      "/usr/bin/nano test.log"
    ],
    "tags": [
      "beats_input_codec_plain_applied"
    ],
    "host.architecture": [
      "x86_64"
    ],
    "cloud.provider": [
      "digitalocean"
    ],
    "@timestamp": [
      "2022-04-29T10:53:54.331Z"
    ],
    "agent.id": [
      "913c66a2-6afc-4579-9ad6-a1e9b1805dae"
    ],
    "cloud.service.name": [
      "Droplets"
    ],
    "ecs.version": [
      "1.12.0"
    ],
    "host.containerized": [
      false
    ],
    "host.os.platform": [
      "ubuntu"
    ],
    "log.file.path": [
      "/var/log/auth.log"
    ],
    "agent.ephemeral_id": [
      "ce7a72e4-5321-48db-ad74-d9be2f47ab0a"
    ],
    "agent.version": [
      "7.17.3"
    ],
    "host.os.family": [
      "debian"
    ],
    "event.dataset": [
      "system.auth"
    ]
  }
}
```
