~>CREATE NONCLUSTERED INDEX [IX_Orders_Customer] ON [dbo].[Orders] ([CustomerId]);
CREATE NONCLUSTERED INDEX [IX_Orders_Status] ON [dbo].[Orders] ([Status]);
CREATE NONCLUSTERED INDEX [IX_Orders_Created] ON [dbo].[Orders] ([CreatedAt]);
CREATE NONCLUSTERED INDEX [IX_Orders_Updated] ON [dbo].[Orders] ([UpdatedAt]);
CREATE NONCLUSTERED INDEX [IX_Orders_Region] ON [dbo].[Orders] ([Region]);
CREATE UNIQUE NONCLUSTERED INDEX [IX_Orders_Ref] ON [dbo].[Orders] ([Reference]);
CREATE NONCLUSTERED INDEX [IX_Orders_Total]
    ON [dbo].[Orders] ([Total]);
create index ix_orders_currency on dbo.orders (currency);
CREATE INDEX IX_Orders_Notes ON Orders (Notes);
