
from enum import Enum
import pandas as pd
import argparse
import json
import glob
import os


class Carbanak_FIN7Eval():
	def __init__(self, filename, strict_mitre=False):
		self._strict_mitre = strict_mitre
		self._vendor = filename.split(os.sep, 2)[-1]
		self._vendor = self._vendor.split('_', 1)[0]
		print('Processing %s' % self._vendor)
		with open(filename, 'r', encoding='utf-8') as infile:
		    data=infile.read()

		self._obj = json.loads(data)
		self._adv = None
		self._df = pd.DataFrame(columns=('Substep', 'Criteria', 'Tactic', 'TechniqueId', 'TechniqueName', 'SubtechniqueId', 'SubtechniqueName', 'Detection', 'Modifiers', 'PowerShell', 'Indicator', 'IndicatorName'))


	def getDetection(self, detections):
		allowModifiers = self._strict_mitre
		ret = {'Detection_Type':'None', 'Modifiers':'', 'Indicator':'', 'Indicator_Name':''} 
		dt = Enum('DetectionTypes', 'None Telemetry General Tactic Technique N/A')
		sev = Enum('Severity', 'Informational Low Medium High Critical')
		for detection in detections:
			# check if we're allowing modifiers
			if not allowModifiers and len(detection['Modifiers']):
				continue
			# checks for a better detection 
			if dt[ret['Detection_Type']].value < dt[detection['Detection_Type']].value:
				ret = detection
			# TODO - is this the same type but higher severity?
#			elif dt[ret['Detection_Type']].value == dt[detection['Detection_Type']].value and len(ret['Indicator']) and sev[ret['Indicator']].value < sev[detection['Indicator']].value:
#				ret = detection
		return (ret['Detection_Type'], ret['Modifiers'], ret['Indicator'], ret['Indicator_Name'])


	# append detection info for the substep to dataframe
	def appendSubstep(self, substep):
		obj = { 'Substep':None, 'Criteria':None, 'Tactic':None, 'TechniqueId':None, 'TechniqueName':None, 'SubtechniqueId':None, 'SubtechniqueName':None, 'Detection':None, 'Modifiers':None, 'Powershell':None, 'Indicator':None, 'IndicatorName':None}
		obj['Substep'] = substep['Substep']
		obj['Criteria'] = substep['Criteria']
		obj['Tactic'] = substep['Tactic']['Tactic_Name']
		obj['TechniqueId'] = substep['Technique']['Technique_Id']
		obj['TechniqueName'] = substep['Technique']['Technique_Name']
		obj['SubtechniqueId'] = substep['Subtechnique']['Subtechnique_Id']
		obj['SubtechniqueName'] = '' if not len(substep['Subtechnique']['Subtechnique_Name']) else substep['Subtechnique']['Subtechnique_Name'].split(': ')[1]

		(obj['Detection'], obj['Modifiers'], obj['Indicator'], obj['IndicatorName']) = self.getDetection(substep['Detections'])
		obj['Powershell'] = True if 'powershell' in obj['Criteria'].lower() else False
		self._df = self._df.append(obj, ignore_index=True)


	# iterator function to process each substep
	def iterSteps(self):
		for scenario in self._adv['Detections_By_Step']:
			for step in self._adv['Detections_By_Step'][scenario]['Steps']:
				for substep in step['Substeps']:
					self.appendSubstep(substep)


	# select adversary to analyze (stubbed out for future)
	def selectAdversary(self, adversary='carbanak_fin7'):
		for adversary in self._obj['Adversaries']:
			if adversary['Adversary_Name'] == 'carbanak_fin7':
				self._adv = adversary
				break
		self.iterSteps()


	# generate vendor performance metrics
def scoreVendor(obj, strict_mitre=False):
	counts = obj.Detection.value_counts()
	try:
		misses = counts['None']
	except KeyError:
		misses = 0
	try:
		tactic = counts['Tactic']
	except KeyError:
		tactic = 0
	try:
		general = counts['General']
	except KeyError:
		general = 0
	try:
		na = counts['N/A']
	except KeyError:
		na = 0
	substeps = len(obj.index) - na
	visibility = substeps - misses
	techniques = counts['Technique']
	analytics = techniques / visibility if not strict_mitre else (techniques + Tactic + General)/substeps
	return (visibility/substeps, analytics)


def parse_args():
	parser = argparse.ArgumentParser(
		description='Query utility for analyzing the MITRE ATT&CK Evaluations'
	)
	parser.add_argument(
		'--strict-mitre',
		help='Override analysis and stick to raw data',
		default=False,
		action='store_true'
	)

	args = parser.parse_args()

	return args


if __name__ == '__main__':

	args = parse_args()
	fname = 'fin7eval.xlsx' if not args.strict_mitre else 'fin7eval-strict-mitre.xlsx'

	dfs = {}
	for infile in sorted(glob.glob(os.path.join('data', '*json'))):
		obj = Carbanak_FIN7Eval(infile, args.strict_mitre)
		obj.selectAdversary('carbanak_fin7')
		dfs.update({obj._vendor: obj._df})

	writer = pd.ExcelWriter(fname, engine='xlsxwriter')
	results = pd.DataFrame(columns=['vendor', 	\
                            		'visibility',	\
                            		'analytics'])

	# Write out results tab
	for vendor in dfs.keys():
		(visibility, analytics) = scoreVendor(dfs[vendor], strict_mitre=args.strict_mitre)
		results = results.append({'vendor':vendor, 'visibility':visibility, 'analytics':analytics},ignore_index=True)
	results.to_excel(writer, sheet_name='Results', index=False)

	# Write out individual vendor tabs
	for vendor in dfs.keys():
		dfs[vendor].to_excel(writer, sheet_name=vendor, index=False, columns=['Substep', 'Criteria', 'Tactic', 'TechniqueId', 'TechniqueName', 'SubtechniqueId', 'SubtechniqueName', 'Detection', 'Modifiers', 'PowerShell', 'Indicator', 'IndicatorName'])
	writer.save()

	print('%s has been written.' % fname)

