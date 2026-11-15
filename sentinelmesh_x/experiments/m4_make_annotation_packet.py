from m1_common import *
from sentinelmesh_x.annotation import build_blinded_packet
S = alert_sets(); attach_trackb(S["test"]); rng = random.Random(SEED) if False else __import__("random").Random(SEED)
sample = rng.sample(S["test"], 60)
items = [{"alert_id": f"{r['run']}|{r['slot']}", "source": r["alertB"]["source"], "event_text": r["qB"], "label": r["truth"]} for r in sample]
h = build_blinded_packet(items, SEED, ROOT / "annotation/annotation_packet_blinded.csv", ROOT / "annotation/_answer_key_team_labels_DO_NOT_SHARE.csv")
print("answer key sha256", h)
