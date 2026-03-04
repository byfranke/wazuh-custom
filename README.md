# Wazuh Custom

Coleção de customizações, integrações e recursos para o Wazuh SIEM — scripts, regras, decoders e dashboards desenvolvidos para aprimorar a detecção e resposta a incidentes de segurança.

## Instalação

1. Clone o repositório:
```bash
git clone https://github.com/byfranke/wazuh-custom.git
```

2. Copie os arquivos de integração para o diretório do Wazuh:
```bash
cp integrations/* /var/ossec/integrations/
chmod 750 /var/ossec/integrations/custom-discord
chmod 750 /var/ossec/integrations/slack
chown root:wazuh /var/ossec/integrations/*
```

3. Configure a integração desejada no `/var/ossec/etc/ossec.conf`

4. Reinicie o Wazuh Manager:
```bash
systemctl restart wazuh-manager
```

## Requisitos

- Wazuh Manager 4.x+
- Python 3.6+
- Módulo `requests` (incluso no Wazuh)

## Contribuições

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues ou pull requests.
