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
- [Chapter 2: ]()
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

