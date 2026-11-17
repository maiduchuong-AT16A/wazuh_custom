import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

PAD, CLS = 256, 257
VOCAB = 259


class Block(nn.Module):
    def __init__(self, d, heads, drop):
        super().__init__()
        self.heads = heads
        self.ln1, self.ln2 = nn.LayerNorm(d), nn.LayerNorm(d)
        self.qkv, self.proj = nn.Linear(d, 3 * d), nn.Linear(d, d)
        self.ff = nn.Sequential(nn.Linear(d, 4 * d), nn.GELU(), nn.Linear(4 * d, d))
        self.drop = nn.Dropout(drop)

    def forward(self, x, mask):
        B, T, D = x.shape
        q, k, v = self.qkv(self.ln1(x)).view(B, T, 3, self.heads, D // self.heads).permute(2, 0, 3, 1, 4)
        a = F.scaled_dot_product_attention(q, k, v, attn_mask=mask)
        x = x + self.drop(self.proj(a.transpose(1, 2).reshape(B, T, D)))
        return x + self.drop(self.ff(self.ln2(x)))


class ByteTransformer(nn.Module):
    def __init__(self, seq, n_src, n_cls, d=256, layers=6, heads=4, drop=0.1):
        super().__init__()
        self.tok = nn.Embedding(VOCAB, d)
        self.pos = nn.Embedding(seq, d)
        self.src = nn.Embedding(n_src, d)
        self.blocks = nn.ModuleList(Block(d, heads, drop) for _ in range(layers))
        self.ln = nn.LayerNorm(d)
        self.head = nn.Linear(d, n_cls)

    def forward(self, ids, src):
        keep = ids != PAD
        x = self.tok(ids) + self.pos.weight[: ids.shape[1]] + self.src(src)[:, None]
        mask = keep[:, None, None, :]
        for b in self.blocks:
            x = b(x, mask)
        x = self.ln(x)
        pooled = (x * keep[..., None]).sum(1) / keep.sum(1, keepdim=True)
        return self.head(torch.cat([x[:, 0:1], pooled[:, None]], 1).mean(1))


class TransformerScorer:
    def __init__(self, path, device=None):
        ck = torch.load(path, map_location="cpu", weights_only=False)
        cfg = ck["cfg"]
        self.cfg, self.ratios = cfg, ck["ratios"]
        self.srcs, self.classes = cfg["srcs"], cfg["classes"]
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.model = ByteTransformer(cfg["seq"], len(self.srcs), len(self.classes),
                                     d=cfg["d"], layers=cfg["layers"], heads=cfg["heads"])
        self.model.load_state_dict(ck["state"])
        self.model.to(self.device).eval()

    def encode(self, texts):
        L = self.cfg["line_len"]
        ids = np.full((len(texts), self.cfg["seq"]), PAD, dtype=np.int64)
        ids[:, 0] = CLS
        for i, t in enumerate(texts):
            b = np.frombuffer(t.encode()[:L], dtype=np.uint8)
            ids[i, 1:1 + len(b)] = b
        return ids

    @torch.no_grad()
    def predict(self, texts, src, batch_size=512):
        si = self.srcs.index(src)
        out = []
        for i in range(0, len(texts), batch_size):
            ids = torch.from_numpy(self.encode(texts[i:i + batch_size])).to(self.device)
            s = torch.full((len(ids),), si, dtype=torch.long, device=self.device)
            if self.device == "cuda":
                with torch.autocast("cuda", dtype=torch.bfloat16):
                    logits = self.model(ids, s)
            else:
                logits = self.model(ids, s)
            out.append(logits.float().softmax(-1).cpu().numpy())
        return np.concatenate(out) if out else np.zeros((0, len(self.classes)))
