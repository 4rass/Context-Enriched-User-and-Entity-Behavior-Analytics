"""Render the default SQLite schema as a PNG and an editable SVG (requires Pillow)."""
from pathlib import Path
import html
import sqlite3
from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).resolve().parent
APP = HERE.parents[1]
connection = sqlite3.connect(f"file:{APP / 'instance/ce_ueba.db'}?mode=ro", uri=True)
W, H = 1920, 1870
canvas = Image.new('RGB', (W, H), '#f1f5f9')
draw = ImageDraw.Draw(canvas)
svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
       '<title>CE-UEBA database entity-relationship diagram</title>',
       '<desc>Six tables with all columns, constraints, and eight foreign-key relationships from the SQLite schema.</desc>']

def box(x, y, w, h, fill, radius=0):
    draw.rounded_rectangle((x, y, x+w, y+h), radius=radius, fill=fill)
    svg.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{radius}" fill="{fill}"/>')

def text(x, y, value, size=21, color='#334155', bold=False):
    font = ImageFont.truetype('/System/Library/Fonts/Supplemental/Arial' + (' Bold' if bold else '') + '.ttf', size)
    draw.text((x, y), value, font=font, fill=color)
    svg.append(f'<text x="{x}" y="{y + size * .91}" font-family="Arial, sans-serif" font-size="{size}" font-weight="{700 if bold else 400}" fill="{color}">{html.escape(value)}</text>')

box(0, 0, W, H, '#f1f5f9')
box(0, 0, W, 190, '#0f172a')
text(60, 35, 'CE-UEBA', 24, '#38bdf8', True)
text(60, 75, 'Database entity-relationship diagram', 44, '#ffffff', True)
text(60, 137, 'Physical SQLite schema  /  Identity, assets, behavioral telemetry and risk decisions', 23, '#cbd5e1')
text(60, 212, 'PK  Primary key     FK  Foreign key     UQ  Unique     NN  Not null     —  Nullable', 22)

tables = [
    ('roles', 'IDENTITY / IAM', '#0f766e'),
    ('users', 'IDENTITY / IAM', '#2563eb'),
    ('it_assets', 'ASSETS / ITAM', '#b45309'),
    ('change_tickets', 'CHANGES / ITSM', '#be123c'),
    ('behavioral_logs', 'TELEMETRY / UEBA', '#7c3aed'),
    ('alerts', 'RISK / SOC', '#c2410c'),
]
relationships = []
for i, (table, category, accent) in enumerate(tables):
    x, y = 60 + (i % 3)*610, 265 + (i // 3)*560
    box(x, y, 580, 535, '#ffffff', 14)
    box(x, y, 580, 8, accent)
    text(x+22, y+23, category, 17, accent, True)
    text(x+22, y+52, table, 30, '#0f172a', True)
    text(x+22, y+102, 'COLUMN', 16, '#64748b', True)
    text(x+365, y+102, 'TYPE', 16, '#64748b', True)
    text(x+493, y+102, 'KEY / NULL', 13, '#64748b', True)
    columns = connection.execute(f'PRAGMA table_info("{table}")').fetchall()
    foreign = {r[3]: r for r in connection.execute(f'PRAGMA foreign_key_list("{table}")')}
    unique = set()
    for idx in connection.execute(f'PRAGMA index_list("{table}")').fetchall():
        if idx[2]:
            fields = connection.execute(f'PRAGMA index_info("{idx[1]}")').fetchall()
            if len(fields) == 1:
                unique.add(fields[0][2])
    for j, (_, name, dtype, nn, default, pk) in enumerate(columns):
        yy = y+137+j*33
        if j % 2 == 0:
            box(x+12, yy-3, 556, 32, '#f8fafc')
        flags = [flag for condition, flag in [(pk, 'PK'), (name in foreign, 'FK'), (name in unique, 'UQ'), (nn and not pk, 'NN')] if condition]
        text(x+22, yy, name, 20, '#0f172a', bool(pk))
        text(x+365, yy, dtype, 16, '#475569')
        text(x+493, yy, ' '.join(flags) or '—', 14, accent, True)
        if name in foreign:
            fk = foreign[name]
            relationships.append((f'{table}.{name}', f'{fk[2]}.{fk[4]}', '1' if nn else '0..1'))

box(60, 1405, 1800, 330, '#ffffff', 14)
text(84, 1428, 'FOREIGN-KEY RELATIONSHIPS', 21, '#0f172a', True)
text(84, 1463, 'Each child references 1 parent (required) or 0..1 parent (nullable). Every parent can have 0..N children.', 21)
for i, (child, parent, cardinality) in enumerate(relationships):
    x, y = 84+(i//4)*895, 1514+(i%4)*48
    text(x, y, child, 21, '#0f172a', True)
    text(x+418, y, '→', 23, '#2563eb', True)
    text(x+456, y, parent, 21)
    text(x+755, y, f'[{cardinality}]', 20, '#2563eb', True)
text(60, 1763, 'Schema note: alerts.log_id is not UNIQUE; SQLite permits multiple alerts per log. ORM uselist=False does not enforce 1:1.', 22)
text(60, 1803, 'Change-ticket correlation is application logic, not a foreign key. Source: instance/ce_ueba.db; reviewed against models.py.', 21, '#64748b')
svg.append('</svg>')
canvas.save(HERE / 'erd_schema.png')
(HERE / 'erd_schema.svg').write_text('\n'.join(svg))
assert len(relationships) == 8
connection.close()
print('Generated erd_schema.png and erd_schema.svg: 6 tables, 8 foreign keys.')
