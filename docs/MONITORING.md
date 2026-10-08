# Monitoring Stash v2 with Wazuh

Stash v2 keeps logins encrypted on the phone and never sends anything to the server, so the server can't see failed unlocks or other activity inside the app. The biggest server-side risk is someone **changing the app files** that the server hands out: tampered code could capture the master password the next time it is unlocked.

Wazuh file integrity monitoring (FIM) closes that gap. Any file added, changed or deleted in the served folder raises a high-severity alert. If you use the [Sentinel SOC dashboard](https://github.com/KevinTechLabs/Homelab-Soc-Dashboard) with its Wazuh integration, that alert also appears in Sentinel and is sent to Discord.

Your own updates trigger it too, which doubles as confirmation that an update landed.

## 1. Watch the folder (on the server that hosts Stash)

Edit the Wazuh agent configuration:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Inside the existing `<syscheck>` section, add a line for the folder Tailscale serves (replace `<user>` with your username):

```xml
<directories realtime="yes" check_all="yes" report_changes="yes">/home/<user>/Documents/stash-v2</directories>
```

- `realtime` reports changes within seconds instead of waiting for the next scheduled scan.
- `report_changes` includes a diff of changed text files in the alert, so you can see exactly what was altered. The app's code isn't secret, so this is safe.

Restart the agent:

```bash
sudo systemctl restart wazuh-agent
```

If this server runs the Wazuh manager itself (an all-in-one install), edit the same file and restart `wazuh-manager` instead.

## 2. Raise the alert level (on the Wazuh manager)

Wazuh's built-in FIM rules (550 changed, 553 deleted, 554 added) are medium severity. Add a rule that escalates any change to the Stash folder:

```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

```xml
<group name="syscheck,stash,">
  <rule id="100900" level="12">
    <if_sid>550, 553, 554</if_sid>
    <field name="file">/Documents/stash-v2/</field>
    <description>Stash app file changed: $(file)</description>
    <mitre>
      <id>T1565.001</id>
    </mitre>
  </rule>
</group>
```

Rule IDs from 100000 upward are reserved for custom rules; if 100900 is already used in your `local_rules.xml`, pick another free number. Restart the manager:

```bash
sudo systemctl restart wazuh-manager
```

## 3. Test it

On the Stash server, create and remove a harmless file:

```bash
touch ~/Documents/stash-v2/fim-test.txt
sleep 15
rm ~/Documents/stash-v2/fim-test.txt
```

You should see two "Stash app file changed" alerts at level 12 in Wazuh, and in Sentinel and Discord if they're connected.

## What this does and doesn't cover

- **Covers:** any change to the files your phone downloads when Stash updates, whether from an attacker, malware or an accidental edit.
- **Doesn't cover:** activity on the phone itself, such as wrong master-password attempts. Stash slows those down on the device (a growing delay after 5 wrong attempts, and Argon2id makes every guess expensive), and they never leave the phone.
- Sentinel's own detections still watch the server: SSH brute force, sudo abuse, new services, and new devices joining the Tailscale network, which is the only way to reach Stash.
