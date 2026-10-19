-- Optional idempotent starter data for a development database.
-- Review permissions and provider-related rows before using in production.
BEGIN;

INSERT INTO currencies (currency_code, currency_name, minor_unit) VALUES
('USD','US Dollar',2),
('INR','Indian Rupee',2),
('EUR','Euro',2),
('GBP','Pound Sterling',2)
ON CONFLICT (currency_code) DO UPDATE SET currency_name = EXCLUDED.currency_name, minor_unit = EXCLUDED.minor_unit;

INSERT INTO roles (role_key, display_name, scope, description) VALUES
('platform_admin','Platform Administrator','platform','Full application administration across workspaces.'),
('workspace_admin','Workspace Administrator','workspace','Manages members, settings, access and workspace resources.'),
('operator','Operator','workspace','Manages configured data, workflows and operational tasks.'),
('standard_user','Standard User','workspace','Uses permitted research and analytics capabilities.')
ON CONFLICT (role_key) DO UPDATE SET display_name = EXCLUDED.display_name, scope = EXCLUDED.scope, description = EXCLUDED.description;

INSERT INTO permissions (permission_key, description) VALUES
('users.manage','Create/deactivate users and manage memberships.'),
('workspace.manage','Manage workspace settings and invitations.'),
('roles.manage','Assign roles subject to last-admin/privilege safeguards.'),
('connectors.manage','Configure approved market-data and structured-data connections.'),
('models.configure','Configure AI models, embedding and retrieval settings.'),
('market_data.read','Read authorized market prices, fundamentals and events.'),
('market_data.manage','Manage data ingestion, refresh and data-quality operations.'),
('portfolio.read','Read authorized portfolios and risk summaries.'),
('portfolio.write','Create/update user-owned portfolio records.'),
('research.read','Search and read authorized research documents.'),
('research.manage','Upload, tag, re-index, share and delete permitted research documents.'),
('ai.use','Use the AI Financial Analyst and approved retrieval tools.'),
('valuation.run','Run DCF valuation and sensitivity calculations.'),
('risk.run','Run portfolio-risk and stress analyses.'),
('datasets.query','Query approved structured sources and datasets.'),
('screen.run','Run saved financial screens.'),
('strategy.manage','Create and version strategy definitions.'),
('backtest.run','Run reproducible strategy backtests.'),
('workflow.execute','Execute approved workflows.'),
('workflow.approve','Approve configured high-impact workflow actions.'),
('reports.create','Create and save analytical reports.'),
('reports.export','Export authorized reports and analysis results.'),
('audit.read','Read permitted administrative and security audit records.')
ON CONFLICT (permission_key) DO UPDATE SET description = EXCLUDED.description;

-- Platform administrator receives all currently seeded permissions.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r CROSS JOIN permissions p
WHERE r.role_key = 'platform_admin'
ON CONFLICT DO NOTHING;

-- Workspace administrator gets workspace/resource administration but not platform-global privileges.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r JOIN permissions p ON p.permission_key IN (
  'workspace.manage','roles.manage','connectors.manage','models.configure',
  'market_data.read','market_data.manage','portfolio.read','portfolio.write',
  'research.read','research.manage','ai.use','valuation.run','risk.run','datasets.query',
  'screen.run','strategy.manage','backtest.run','workflow.execute','workflow.approve',
  'reports.create','reports.export','audit.read'
)
WHERE r.role_key = 'workspace_admin'
ON CONFLICT DO NOTHING;

-- Operators run configured ingestion/workflows and analyses; permissions to edit access/security remain with admins.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r JOIN permissions p ON p.permission_key IN (
  'market_data.read','market_data.manage','portfolio.read','research.read','research.manage',
  'ai.use','valuation.run','risk.run','datasets.query','screen.run','strategy.manage',
  'backtest.run','workflow.execute','reports.create','reports.export'
)
WHERE r.role_key = 'operator'
ON CONFLICT DO NOTHING;

-- Standard users can research and run analytical features on resources they are authorized to access.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r JOIN permissions p ON p.permission_key IN (
  'market_data.read','portfolio.read','portfolio.write','research.read','ai.use',
  'valuation.run','risk.run','datasets.query','screen.run','workflow.execute',
  'reports.create','reports.export'
)
WHERE r.role_key = 'standard_user'
ON CONFLICT DO NOTHING;

INSERT INTO financial_metric_definitions (metric_key, display_name, description, canonical_unit, is_derived) VALUES
('revenue','Revenue','Reported revenue/sales for a stated financial period.','currency',false),
('operating_income','Operating Income','Operating income before financing and tax.','currency',false),
('net_income','Net Income','Reported profit/loss for a financial period.','currency',false),
('diluted_eps','Diluted EPS','Diluted earnings per share as reported.','currency_per_share',false),
('diluted_shares_outstanding','Diluted Shares Outstanding','Diluted share count applicable to the stated period.','shares',false),
('cash_and_equivalents','Cash and Cash Equivalents','Cash and equivalent balance from a balance sheet.','currency',false),
('total_debt','Total Debt','Debt amount according to the selected data definition.','currency',true),
('capital_expenditure','Capital Expenditure','Cash spent on property, plant and equipment or equivalent.','currency',false),
('depreciation_amortization','Depreciation and Amortization','Reported or standardized D&A.','currency',false),
('change_in_working_capital','Change in Working Capital','Change in operating working capital used by the DCF model.','currency',true),
('operating_cash_flow','Operating Cash Flow','Cash flow from operations.','currency',false),
('free_cash_flow','Free Cash Flow','FCF under the configured formula definition.','currency',true),
('market_capitalization','Market Capitalization','Market capitalization as of a stated timestamp.','currency',true),
('price_to_earnings','Price-to-Earnings Ratio','Price divided by the selected earnings measure.','ratio',true),
('dividend_yield','Dividend Yield','Dividend yield under the configured convention.','percent',true),
('total_assets','Total Assets','Reported total assets.','currency',false),
('total_liabilities','Total Liabilities','Reported total liabilities.','currency',false),
('shareholders_equity','Shareholders Equity','Reported total shareholders equity.','currency',false)
ON CONFLICT (metric_key) DO UPDATE SET
  display_name = EXCLUDED.display_name,
  description = EXCLUDED.description,
  canonical_unit = EXCLUDED.canonical_unit,
  is_derived = EXCLUDED.is_derived;

INSERT INTO technical_indicator_definitions (indicator_key, display_name, description, calculation_version, parameter_schema, default_parameters, output_units) VALUES
('SMA','Simple Moving Average','Arithmetic mean of prices over a rolling window.','v1', '{"period":{"type":"integer","min":1,"max":500}}'::jsonb, '{"period":20}'::jsonb, 'price'),
('EMA','Exponential Moving Average','Exponentially weighted moving average.','v1', '{"period":{"type":"integer","min":1,"max":500}}'::jsonb, '{"period":20}'::jsonb, 'price'),
('RSI','Relative Strength Index','Momentum oscillator calculated over a configured period.','v1', '{"period":{"type":"integer","min":2,"max":200}}'::jsonb, '{"period":14}'::jsonb, 'index_0_100'),
('MACD','Moving Average Convergence Divergence','Difference between configured fast and slow EMAs with signal line.','v1', '{"fast_period":{"type":"integer","min":1},"slow_period":{"type":"integer","min":2},"signal_period":{"type":"integer","min":1}}'::jsonb, '{"fast_period":12,"slow_period":26,"signal_period":9}'::jsonb, 'price_difference'),
('BBANDS','Bollinger Bands','Moving average and bands at configured standard deviations.','v1', '{"period":{"type":"integer","min":2,"max":500},"stddev":{"type":"number","min":0.1,"max":5}}'::jsonb, '{"period":20,"stddev":2}'::jsonb, 'price'),
('ATR','Average True Range','Range-based volatility indicator.','v1', '{"period":{"type":"integer","min":1,"max":500}}'::jsonb, '{"period":14}'::jsonb, 'price'),
('OBV','On Balance Volume','Cumulative volume indicator based on close-to-close direction.','v1', '{}'::jsonb, '{}'::jsonb, 'volume')
ON CONFLICT (indicator_key) DO UPDATE SET
  display_name = EXCLUDED.display_name,
  description = EXCLUDED.description,
  calculation_version = EXCLUDED.calculation_version,
  parameter_schema = EXCLUDED.parameter_schema,
  default_parameters = EXCLUDED.default_parameters,
  output_units = EXCLUDED.output_units;

COMMIT;
