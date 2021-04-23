# CarbanakFin7Eval
This project is focused on performing and facilitating analysis of the round 3 results from MITRE's Enterprise ATT&CK Evaluation. This year, I find myself in a different situation than in years past, where now I'm working for one of the vendors who participated in this evaluation. Given this complexity, I've added a --strict-mitre flag to override any of the analysis I describe below, if you just want to use their numbers. I think the changes I discuss below are important, and there's a multi-year history of my evaluating vendors using these methods, but the purpose of this project is to allow you to do your own analysis. For a detailed discussion on what you should be thinking about when analyzing these results, I recommend you check out my blog on the subject https://medium.com/the-recovering-analyst/dont-let-vendor-exuberance-distract-from-the-value-of-the-mitre-att-ck-evaluation-b57a1ccab2a4.

The output of the CarbanakFin7Eval.py script will output an XLSX workbook that will allow you to parse and play with vendor scores based on the analysis I've performed for the past 3 years. This analysis differs from MITRE's published metrics in three important ways:
1) I exclude any detection that is either "delayed" or due to a "configuration change." The reason for this is because the delay was significant enough for MITRE to highlight it, and I don't believe customers are going to benefit from the same "configuration changes" that are being performed in a test environment.
2) I focus on ATT&CK Technique detections in evaluating the analytic capabilities of a product while MITRE includes General, Tactics, and Techniques. My feeling is that is we're trying to assess the quality of a security analytic capability and need to set a high bar. Let's be honest, there's only 13 Tactics and some Techniques fall in multiple Tactics... so Tactics detections just aren't that interesting (for example).
3) I create orthogonality between Visibility and Analytics by dividing the number of Technique detections by Visibility and not the total number of Substeps to allow vendors with weaker Visibility to still highlight the quality of their security analytics capabilities.  

This year, I'm including the XLSX in the source tree to save trouble running the code if that's all you care about. If you don't like the decisions I've made above, the code is yours to modify.

## Requirements
python3

curl (to download the json data)

## FAQ
Q: Why do you find more 'None' values than are reported when I grep for it?

A: There are instances where the scoring will show a detection with some negative modifier and no other detection for that substep, therefore, the number of 'None' detections I report in the xlsx may be higher than what you get when you grep these files.


Q: Why don't you count config changes?

A: I'm trying to identify what a majority of companies would be looking at when trying to do a detection. You have to assume these products have been tuned for the evaluation, so I'm just enforcing that the tuning stop before the evaluation begins. 


Q: Is there a more in depth analysis of this data anywhere?

A: I recommend you check out my blog on the subject of analyzing this years' results... https://medium.com/the-recovering-analyst/dont-let-vendor-exuberance-distract-from-the-value-of-the-mitre-att-ck-evaluation-b57a1ccab2a4.


## Thanks
I want to thank MITRE for the ATT&CK Framework and for performing these open and transparent evaluations.

I also want to thank the vendors who participated in this evaluation for providing transparency into the efficacy of their products. 

You are all making the world more secure.
