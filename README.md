# M-FIREWALL Clean

Version ordenada del proyecto de firewall con PySide6 e iptables.

Cumple la rubrica:

- Bloquea Facebook, YouTube y Hotmail.
- Bloquea paquetes cliente -> servidor y permite servidor -> cliente.
- Bloquea acceso/envio de equipos clientes por MAC.
- Limita conexiones simultaneas por IP cliente.
- Registra paquetes rechazados con prefijo `PM-DROP`.
- Guarda reglas en archivo personalizado: `/opt/proyecto-m-clean/rules/project_m.rules.v4`.
- No usa `/etc/sysconfig/iptables`.

## Estructura

- `app/core/`: logica de configuracion, red, DNS, ipset e iptables.
- `app/ui/`: ventana PySide6.
- `config/`: ejemplo de configuracion.
- `scripts/`: instalador y diagnostico.
- `rules/`: salida esperada de reglas generadas.

## Instalar en Kali

```bash
cd ~/proyecto-m-firewall-clean
sudo bash scripts/install.sh
./run.sh
```

## Probar bloqueo

1. Pulsa `Detectar IP`.
2. Activa YouTube.
3. Configura cliente-servidor, MAC o limites si el docente lo pide.
4. Pulsa `Guardar y Activar`.
5. Espera los mensajes `[OK]` de la consola y la tarjeta `Estado real del cortafuegos`.
6. En el cliente usa el comando que aparece en la app:

```bash
sudo ip route replace default via IP_DE_KALI
```

La app verifica automaticamente:

- `PM_WEBBLOCK` existe y apunta a `PM_REJECT`.
- `OUTPUT` pasa por `PM_WEBBLOCK` para bloquear la propia Kali.
- `FORWARD` pasa por `PM_WEBBLOCK` para bloquear clientes.
- `PM_YOUTUBE` tiene entradas.
- `dnsmasq` y `/etc/hosts` quedaron configurados.

Si YouTube estaba abierto antes de aplicar, cierra esa pestaña o reinicia el navegador. La app limpia DNS y conntrack, pero el navegador puede conservar conexiones/cache propias por unos segundos.

Al cerrar la app, pregunta si quieres restaurar todo a valores predeterminados o dejar el cortafuegos activo.

## Diagnostico

```bash
sudo bash scripts/diagnose.sh
```

Para que YouTube quede bloqueado deben existir:

- `PM_WEBBLOCK` en iptables.
- `PM_YOUTUBE` en ipset.
- Reglas en `OUTPUT` o `FORWARD` apuntando a `PM_WEBBLOCK`.
- Cadenas `PM_CLISRV`, `PM_MACBLOCK`, `PM_CONNLIMIT`.
- `dnsmasq` activo con dominios de YouTube en `/etc/dnsmasq.d/proyecto-m-youtube.conf`.

## Cadenas iptables

- `PM_WEBBLOCK`: bloqueo de sitios por ipset y SNI.
- `PM_CLISRV`: bloqueo unidireccional cliente -> servidor.
- `PM_MACBLOCK`: bloqueo por direccion MAC.
- `PM_CONNLIMIT`: limite de conexiones simultaneas.
- `PM_REJECT`: log + accion final.
