source /home/admin2/docu_agentro/docs/12-CASES-REPORTS/vanko-report/setenv.sh
cd /home/admin2/docu_agentro/docs/12-CASES-REPORTS/vanko-report
echo "WORKFLOW Phase C — get_recmd on UsrClass.dat (ShellBags — folder-tree browsing)"
$MCP get_recmd '{"hive":"/tmp/agentropix-sift-vanko/PC/UsrClass.dat","timeout_seconds":200}' | tee step_022_recmd_usrclass.json | python3 -c "import sys,json;d=json.load(sys.stdin);print('  entries:',d.get('entry_count'),'| error:',d.get('error'))"
