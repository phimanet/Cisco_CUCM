# Release Tag Playbook

Use tags before every deploy so rollback is deterministic.

## 1) Create a release tag before pull/deploy

```bash
cd /opt/cucm-web && git fetch origin && git checkout main && git pull origin main && git tag -a release-$(date +%Y%m%d-%H%M%S) -m "Pre-deploy snapshot" && git push origin --tags
```

## 2) Confirm current running commit

```bash
cd /opt/cucm-web && git rev-parse --short HEAD && git log -1 --oneline
```

## 3) Roll back to a known tag

```bash
cd /opt/cucm-web && git fetch --tags && git reset --hard <tag-name> && sudo systemctl restart cucm-web && sudo systemctl status cucm-web --no-pager
```

## 4) Optional: pin to a specific clean-slate commit

```bash
cd /opt/cucm-web && git fetch origin && git reset --hard <commit-sha> && sudo systemctl restart cucm-web && sudo systemctl status cucm-web --no-pager
```

## 5) Run parity check after deploy/rollback

```bash
cd /opt/cucm-web && bash scripts/check_env_parity.sh /opt/cucm-web cucm-web
```

## Notes

- Tags are lightweight release anchors and should be pushed to origin.
- Use one new tag per production change window.
- Keep LAB and PROD on explicit commit hashes before testing new enhancements.
