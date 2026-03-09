<p align="center"> 
<img src="Manning-Investing-for-Programmers-2025.png">
</p>

# Investing for Programmers: Understanding markets through data and code
## Written by Stefan Papp, published by Manning, 2025
- [**Amazon URL**](https://www.amazon.com/Investing-Programmers-Stefan-Papp/dp/1633435806/)
- [**Original Books Notes**](Manning-Investing-for-Programmers-2025.txt)

| Chapter |Brief Notes |
|---------|------------|
| Chapter 1 | introduces you to the investment domain and how programmers can excel. |
| Chapter 2 | teaches financial basics and introduces you to key metrics for exploration. |
| Chapter 3 | demonstrates collecting financial data using Python libraries, including Yahoo Finance and alternative libraries. |
| Chapter 4 | teaches you how to create an investment thesis to look for growth portfolios. |
| Chapter 5 | explains how to look for portfolios to create passive income. |
| Chapter 6 | demonstrates how to collect data from brokers and exchanges, centralize all holdings in one place, and facilitate their analysis. |
| Chapter 7 | explains how to investigate risks and learn ways to hedge them. We look at Sharpe ratios and other methods. |
| Chapter 8 | introduces AI for investment analysis. We introduce machine learning use cases and explore the application of generative AI in investment research. |
| Chapter 9 | demonstrates how to use AI agents for more advanced use cases, enabling data exploration and the integration of additional data sources. |
| Chapter 10 | shows how to display charts and technical analysis. You learn how to create charts using Bollinger Bands and other frameworks. |
| Chapter 11 | explores algorithmic trading and the application of nonfinancial data in financial analysis. |
| Chapter 12 | explores private equity as a form of ownership in startups and how to make informed investment decisions. |
| Chapter 13 | summarizes what you learned and provides some final thoughts for the path ahead. |

## Table of Contents
- [Chapter 1: The analytical investor](#chapter-1-the-analytical-investor)
- [Chapter 2: Investment essentials](#chapter-2-investment-essentials)
- [Chapter 3: ]()
- [Chapter 4: ]()
- [Chapter 5: ]()
- [Chapter 6: ]()
- [Chapter 7: ]()
- [Chapter 8: ]()
- [Chapter 9: ]()
- [Chapter 10: ]()
- [Chapter 11: ]()
- [Chapter 12: ]()
- [Chapter 13: ]()


**liveBook discussion forum**        https://livebook.manning.com/book/investing-for-programmers/discussion


# Chapter 1: The analytical investor
### [top](#table-of-contents)

An **asset** is something we can purchase to monetize.

The term **securities** refers to a group of assets in the financial domain, such as stocks and bonds. 

In general, assets are monetized in two ways:
- Capital appreciation—For example, buy low and sell high.
- Passive income—For example, getting regular payments (interest payments on savings accounts or receiving rent from a tenant).

Stock represents ownership, also known as equity. When you buy stocks, you acquire a small part of a company.

Through a brokerage account, investors buy shares (referring to a countable amount) of the company’s stock (representing the total assets of a company.

A **portfolio** is a collection of securities (stocks, bonds, options, etc.) that you own.

If a position in your portfolio is higher than its purchase price, you have an unrealized gain until you sell it to realize the gain.

The same logic applies to `unrealized` and `realized` losses.

Some stocks offer income to investors through a small payment per share, known as a **dividend**.

Most ETFs are passively managed, meaning they track a market index automatically, such as the S&P 500.

Algorithms are used to rebalance the fund’s holdings, keeping it aligned with its index.

In actively managed ETFs, a portfolio manager selects specific investments to buy.

- Mutual funds—These funds are similar to ETFs in that they provide diversification and are highly regulated. The primary operational difference is that mutual funds only trade once a day at a price determined after the market closes, known as the net asset value (NAV).
- Hedge funds—These funds are typically less regulated, require a substantial minimum investment, and are generally accessible only to wealthy investors.

### Derivatives
- A put option gives the buyer the right, but not the obligation, to sell an asset at a set price (the strike price). It’s a type of insurance.
- A call option gives the buyer the right, but not the obligation, to buy an asset at a specified strike price. It’s a way to bet on a price increase with limited risk.

Investing involves acquiring assets and monetizing them, either through  capital gains or passive income.

An asset is considered non-fungible if it’s unique and can’t be easily replaced by another identical item.

In contrast, fungible assets are interchangeable, which makes them a good starting point for new investors.

This interchangeability allows them to be traded easily and efficiently.

**Candlestick charts** help us evaluate stock performance over multiple days.
- `Black` (or `red`) shows that a stock’s price decreased, while `white` (or `green`) shows that it increased during the day.

We can classify investment styles into three main categories: value, growth, and income investing. These categories sometimes overlap.

One approach is called Growth at a Reasonable Price (**GARP**), which combines value and growth investing.

### page 38
**Table 1.1 Comparing growth, value, and income investing**

| Attribute | Growth investing | Value investing | Income investing |
|-----------|------------------|-----------------|------------------|
| Primary goal | Capital appreciation | Capital appreciation | Regular income |
| Investor focus | Future potential, innovation | Undervalued “bargains” | Consistent cash payouts |
| Typical company | Young, innovative, rapidly expanding | Mature, stable, temporarily unpopular | Established, predictable, high cash flow |
| Dividends | Low or none (profits are reinvested) | Often pays dividends | High and stable dividends key |
| Key metrics | High revenue growth, High P/E | Low P/E, Low P/B* | High dividend yield, stable cash flow |
| Risk profile | High | Low to moderate | Low |
| Time horizon | Long-term | Medium to long term | Any, but often for immediate needs |

**P/E = price-to-earnings; P/B = price-to-booking.**


# Chapter 2: Investment essentials
### [top](#table-of-contents)

-  Income statement—How much revenue a business makes and how much it spends
-  Balance sheet—What assets a business owns and what it owes
-  Cashflow statement—How much cash the business generates


**Investopedia**        https://www.investopedia.com/

The main components of an income statement are as follows:
-  Revenue—Total income from sales or services
-  Expenses—Costs incurred to generate revenues
-  Net income—Revenue minus expenses, indicating profit or loss


》 Just by looking at the increased R&D expenses without any further details, we can take a guess at what’s going on here to come up with theories and create a bullish
(optimistic) and a bearish (pessimistic) hypothesis.

### Revenue to Expenses Distribution Example:
- revenue 100%
  - R&D      5%
  - expenses 80%
    - services 60%
    - other expenses 20%
  - surplus 15%


**Simple Balance sheet**
> Assets = Liabilities + Shareholders’ equity

> Assets are what a company owns, liabilities are what it owes, and shareholder equity is the amount shareholders would get paid 
>> if all assets were liquidated and the debts were paid. A company may be in serious trouble when its liabilities exceed its assets.

> Liquidity is a metric that tells how easily an asset can be converted to cash.

> Free cash flow = Operating cash flow – Capital expenditures


### page 51
Why cash flow matters
- categorization of sectors according to the Global Industry Classification Standard (GICS) of S&P
  - https://www.spglobal.com/spdji/en/landing/topic/gics/
  - a standard used to categorize companies based on their business models.

### page 53
Table 2.1 GICS sectors and their influences

| Sector | What it does | Influenced by |
|--------|--------------|---------------|
| Utilities | Companies that provide essential services such as electricity,</br>water, and natural gas | Interest rates, energy prices, regulation, and bond yields |
|Consumer Staples | Companies that produce essential products such as food, beverages,</br>and household items | Interest rates, inflation, consumer confidence, and raw material costs |
| Consumer Discretionary | Companies that produce nonessential goods and services, including</br>automobiles, apparel, and leisure | Consumer spending, unemployment rates, and disposable income |
| Communication Services | Companies that provide communication services, including telecom</br>and media | Government regulation, intense competition, technology changes, general</br>economic conditions, consumer and business confidence, spending, and</br>changes in consumer and business preferences |
| Real Estate | Companies involved in the development, management, and operation of</br>real properties | Demographic changes, interest rates, economic cycle, government policies,</br>housing demand, and economic growth | 
| Information Technology | Companies that produce software, hardware, or semiconductor equipment,</br>and companies that provide internet or related services | Innovation, cybersecurity threats, and regulatory changes |
| Energy | Companies that play a role in extracting, refining, or supplying</br>consumable fuels | Oil prices, geopolitical stability, and renewable energy trends |
| Health Care | Companies that provide medical services, manufacture medical</br>equipment, or develop pharmaceuticals | Pandemics, regulation, drug pricing, and demographic changes |
| Financials | Companies that provide financial services, including banking,</br>insurance, and investment | Interest rates, economic cycles, and regulatory changes |
| Industrials | Companies that produce goods used in construction and manufacturing,</br>including machinery and equipment | Manufacturing output, trade policies, and commodity prices |
| Materials | Companies that provide raw materials used in the manufacturing</br>process, including metals and chemicals | Commodity prices, supply chain stability, and environmental regulations |

**Warren Buffett** recommends investing **only** in businesses that you understand.

> Some companies are highly cyclical, with their success directly tied to the health of the economy.
In contrast, others are noncyclical or defensive, remaining stable during economic downturns.


We can group companies as follows (with some slight variations in different markets):
-  Mega-cap—Market   value of `$200 billion` or more
-  Large-cap—Market  value between `$10 billion` and `$200 billion`
-  Mid-cap—Market    value between `$2 billion` and `$10 billion`
-  Small-cap—Market  value between `$250 million` and `$2 billion`
-  Micro-cap—Market  value of less than `$250 million`

Web pages such as the Terms page from `FullRatio` https://fullratio.com/terms give more context to what each ratio could mean for an industry.


### page 58
**Liquidity**

In the simplest terms, `liquidity` measures a company’s ability to pay bills.

The current ratio measures a company’s ability to pay its short-term liabilities with its assets.
This is calculated by dividing the current assets by the current liabilities. We can collect both values from the balance sheet.

The quick ratio is more stringent. It only considers assets, such as cash, marketable securities, and receivables, that the company
 can use to pay short-term debts today and omits assets such as inventory.

`current ratio` > `quick ratio`

Technology companies tend to have higher liquidity ratios, which can also be explained by their business models.


> In a financial sense, debt is all liabilities with interest-bearing obligations.
The `debt-to-equity` (D/E) ratio is calculated by dividing a company’s total liabilities by its total shareholders’ equity.
This ratio is a key indicator of a company’s financial leverage, showing the proportion of debt used to finance its assets compared to equity.
A higher ratio indicates a greater reliance on debt financing, which can increase financial risk.


- earnings per share (EPS) = (Profit – Preferred dividends) ÷ Shares outstanding
- Free cash flow (FCF) = Operating cash flow – CapEx
- Free cash flow per share = Free cash flow (FCF) ÷ Shares outstanding


### page 63
Table 2.8 Earnings ratios for NVIDIA (tech), Apple (tech), Sempra (utility), Walmart (supermarket chain), and Coca-Cola (beverages)

Data taken from Seeking Alpha on June 8, 2025 https://seekingalpha.com

| Company | Forward P/E | Trailing P/E | PEG ratio | Price-to-sales | Price-to-book | Beta |
|---------|-------------|--------------|-----------|----------------|---------------|------|
| NVIDIA (NVDA) | 34.40 | 45.72 | 1.76 | 23.27 | 41.22 | 2.122 |
| Apple (AAPL) | 24.54 | 31.76 | 1.85 | 7.61 | 45.10 | 1.211 |
| Sempra (SRE) | 14.95 | 16.89 | 2.03 | 3.76 | 1.63 | 0.656 |
| Walmart (WMT) | 35.83 | 41.65 | 3.72 | 1.14 | 9.32 | 0.693 |
| Coca-Cola (KO) | 24.02 | 28.65 | 4.41 | 6.55 | 11.72 | 0.46 |


- profitability = earnings - expenses
- Return on assets (ROA) = net income ÷ total assets
  - It reflects how effectively the company uses its assets to generate revenue.
- Return on equity (ROE) = net income ÷ shareholder equity
  - It indicates how effectively a company compensates its shareholders for their investment.


### page 67
Table 2.10 Looking at a dividend scorecard from data collected via Python

| Company | Sector | Industry | Dividend yield | Payout ratio |
|---------|--------|----------|----------------|--------------|
| Microsoft (MSFT) | Technology | Software - Infrastructure | 0.71 | 0.2442 |
| Walmart (WMT) | Consumer Defensive | Discount Stores | 0.96 | 0.3665 |
| NVIDIA (NVDA) | Technology | Semiconductors | 0.03 | 0.0129 |
| Sempra (SRE) | Utilities | Utilities - Diversified | 3.36 | 0.4404 |
| Apple (AAPL) | Technology | Consumer Electronics | 0.51 | 0.1558 |
| Altria (MO) | Consumer Defensive | Tobacco | 6.89 | 0.6779 |
| VICI Properties (VICI) | Real Estate | REIT - Diversified | 5.50 | 0.650 |
| International (RBI.VI) | Financial Services | Banks - Regional | 4.06 | 0.4297 |


A public company can alter its share value by changing the number of outstanding shares:
-  Issuing new shares—When a company issues additional stock, it increases the total supply, thereby diluting the ownership stake of existing shareholders.
-  Repurchasing shares (buybacks)—Conversely, when a company repurchases its stock, it reduces the number of outstanding shares, thereby concentrating ownership and potentially increasing the value of the remaining shares.


**the investment platform Seeking Alpha**               https://seekingalpha.com/

-  SA Analyst Rating
  - An aggregation of crowdsourced ratings by platform users
-  Wall Street Rating
  - An aggregation of ratings by professional Wall Street analysts
-  Quant Rating
  - A rating calculated by a Seeking Alpha algorithm

For the **latest numbers**, go to https://seekingalpha.com/

### page 71
Table 2.13 Company ratings based on the Seeking Alpha platform

| Company | SA analyst rating | Wall Street rating | Quant rating |
|---------|-------------------|------|--------------|
| NVIDIA (NVDA) | 3.83 | 4.56 | 3.38 |
| Pfizer (PFE) | 3.18 | 3.56 | 3.40 |
| Aeva Technologies (AEVA) | 2.50 | 4.40 | 4.99 |
| Innoviz (INVZ) | — | 4.25 | 3.35 |
| Ouster (OUST) | 3.33 | 5.00 | 4.50 |
| Luminar Technologies (LAZR) | 3.25 | 2.75 | 2.63 |

**Treating `statements of experts` as `opinions`, not as `predictions`.**





### [top](#table-of-contents)
### [top](#table-of-contents)
### [top](#table-of-contents)
### [top](#table-of-contents)
### [top](#table-of-contents)
### [top](#table-of-contents)
### [top](#table-of-contents)
### [top](#table-of-contents)
### [top](#table-of-contents)
