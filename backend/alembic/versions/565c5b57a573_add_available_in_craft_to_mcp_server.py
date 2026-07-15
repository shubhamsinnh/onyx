"""add available_in_craft to mcp_server

Revision ID: 565c5b57a573
Revises: bd38e2a494ff
Create Date: 2026-07-15 14:56:39.502921

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "565c5b57a573"
down_revision = "bd38e2a494ff"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "mcp_server",
        sa.Column(
            "available_in_craft",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("mcp_server", "available_in_craft")
