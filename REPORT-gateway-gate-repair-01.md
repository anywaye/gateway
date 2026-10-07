# REPORT-gateway-gate-repair-01 — the two pre-existing reds in gateway's gate

**Branch:** `worker/gateway-w48-gaterepair` (cut from master `ce55b8d`)
**Commits:** `e907111` (Fix 1), `aba7f2c` (Fix 2)
**Gate:** `mise exec -- ./bin/prime` — **exit 0**, output pasted verbatim below.

The worktree was clean on arrival; the previous attempt left nothing behind, so
both fixes were written from scratch against master `ce55b8d`.

## Defect 1 — the port-probe test asserted an environment, not the probe

**Where:** `cmd/gateway/main_test.go:120`,
`TestAnUnsetPortProbesTheDefaultTheServerListensOn`.

**What was wrong:** the case asserted `healthcheck() == 1` with `PORT` unset, on
the premise that *nothing is listening on 8080*. That premise is an environmental
assumption. On the operator's machine OrbStack (PID 856) holds `*:8080`, so the
probe found a listener, answered non-2xx-or-2xx, and the case failed
deterministically — `healthcheck() with an unset PORT = 0, want 1`. CI has no
OrbStack, so CI never saw it: the repository was green in CI and red for the
operator, which is the worst combination, because the operator's red reads as
"the gate is broken" and the CI green reads as "the gate is fine", and they are
the same gate.

**Fix chosen — the brief's "best" option: make the default port injectable.**
`httpapi.DefaultPort` was a `const`; it is now a `var`
(`internal/httpapi/runtime.go:266`), and the test:

1. binds `127.0.0.1:0` and reads a free port out of the listener,
2. starts a real HTTP server on it answering 200,
3. sets `httpapi.DefaultPort` to that port (restoring it via `t.Cleanup`),
4. asserts `healthcheck() == 0` with `PORT` unset — the **positive** form: unset
   `PORT` resolves to the default, and the default answers,
5. closes the server and listener, then asserts `healthcheck() == 1` — the pair
   proves the probe's aim tracks the injected default rather than a hardcoded
   8080 (a probe that ignored the default and dialled 8080 anyway would fail
   here on any machine where 8080 is silent, and would have failed the second
   assertion on the operator's machine even with OrbStack answering 2xx).

This is stronger than the case it replaces: the old assertion could be satisfied
by a probe that refused to build a URL and answered 1 for the wrong reason; the
new pair cannot. The export and its "one caller" comment were updated to say
what is now true — one production caller, one test writer, and production code
never writes the var. No second copy of the port number was introduced;
`portFromEnv` still reads the unexported `defaultPort` const, so there is
exactly one 8080 in the tree.

The case was not deleted, not weakened to `>= 0`, and not skipped.

## Defect 2 — the expiry boundary was anchored to the wrong "now"

**Where:** `internal/sessionredis/redis_test.go:166`,
`TestTheExpiryBoundaryIsInclusive`.

**What was wrong:** the table literal computed all three `expires` values with
`time.Now()` **when the slice was built**, while each subtest read its own fixed
clock **inside the subtest** (`now := time.Now()`). So "a millisecond after now"
was `T_build + 1ms`, measured against a store clock of `T_build + (time spent
running subtests 1 and 2)`. On a loaded machine that gap exceeds 1ms, the
boundary flips, and the third row fails: `a session expiring a millisecond after
now is live=false, want true`. Measured by W35: `-count=10` on this commit FAIL
(10/10), on the parent PASS — the answer tracked machine load, not the code.

**Fix chosen — re-anchor each case to the subtest's fixed clock**, exactly as
the brief prescribes: the table now carries an **offset**
(`-time.Millisecond`, `0`, `+time.Millisecond`) instead of an absolute instant,
and `expires := now.Add(tc.offset)` is computed **after** `now := time.Now()`
inside the subtest. Every row is now measured against the same instant the store
uses, and no row spends the next row's margin. The middle row's comment ("the
clock is FIXED, so 'exactly now' is exactly true rather than a race against the
wall clock") stays true, and the third row is exactly true too: with
`expires = now.Add(time.Millisecond)` and the store's clock pinned at `now`,
`expiresAt.After(now)` is true by a full millisecond with no wall clock in the
comparison at all. (The sub-millisecond truncation in `Put`'s `UnixMilli` cannot
break any row: the boundary rows differ from `now` by whole milliseconds, and
the "exactly now" row truncates to an instant `<= now`, which is the inclusive
expiry the case asserts.)

**Flake proof, the way the worker that found it did — under load:**

```
$ go test -count=10 ./internal/sessionredis/
ok  	github.com/cafaye/gateway/internal/sessionredis	1.453s

$ go test ./internal/sessionredis/
ok  	github.com/cafaye/gateway/internal/sessionredis	1.178s
```

`-count=10` passing is the evidence the fix holds: the same command failed
10/10 on the unfixed commit.

## The gate

`mise exec -- ./bin/prime`, on this machine, with OrbStack holding `*:8080`.
The 13 `SKIP`s are the live Redis tier (`GATEWAY_REDIS_URL` unset) — expected,
and left alone. No new skip was added anywhere. Exit code 0. Output verbatim:

```
==> toolchain: go 1.26.1 (mise.toml pins 1.26.1)
go version go1.26.1 darwin/arm64
image tag: Dockerfile and docker-compose.yml build on go 1.26, the major.minor mise.toml pins as 1.26.1

==> gofmt -l
every file under ./cmd and ./internal is gofmt-clean

==> go build ./...

==> go vet ./...

==> go test ./...
--- PASS: TestTheHealthProbeAnswersForBothAnswers (0.00s)
--- PASS: TestTheHealthProbeFailsWhenNothingIsListening (0.00s)
--- PASS: TestTheHealthProbeAimsAtPort (0.00s)
--- PASS: TestAnUnsetPortProbesTheDefaultTheServerListensOn (0.00s)
ok  	github.com/cafaye/gateway/cmd/gateway	0.383s
?   	github.com/cafaye/gateway/internal/api	[no test files]
?   	github.com/cafaye/gateway/internal/api/stripbaseurl	[no test files]
--- PASS: TestTheKeySetCacheHasABoundedTTLAndRefreshesOnAnUnknownKid (0.17s)
--- PASS: TestKeyRefreshIsSingleFlight (0.10s)
--- PASS: TestTheSingleFlightIsTheLockAndNotTheStatementOrder (0.00s)
--- PASS: TestOnlyRS256IsAccepted (0.04s)
--- PASS: TestExpiryAndNotBeforeAreVerifiedAndNoLifetimeCeilingExists (0.05s)
--- PASS: TestAnUnreachableIdentityIsA503AndNeverA401 (0.13s)
--- PASS: TestABrokenConfigurationIsARefusalToBoot (0.00s)
ok  	github.com/cafaye/gateway/internal/auth	1.433s
--- PASS: TestTheLimiterAnswersWhatEachCaseSaysItAnswers (0.03s)
--- PASS: TestTheGoSideCountsRoutedTraffic (0.02s)
--- PASS: TestTheClockTheLimiterReadsIsTheOneTheFixtureClaims (0.00s)
--- PASS: TestTheInventoryIsEveryScenarioDeclaredAndNothingTwice (0.00s)
--- PASS: TestTheAuthPrefixIsRegisteredSoItsRefusalIsTheRouters (0.00s)
ok  	github.com/cafaye/gateway/internal/equivalence	1.478s
--- PASS: TestTheAssertionIsGatewaySignedAndNotTheCallersToken (0.08s)
--- PASS: TestTheAssertionVerifiesAgainstThePublishedJWK (0.09s)
--- PASS: TestTheAssertionIsBoundToTheUpstreamAndShortLived (0.21s)
--- PASS: TestAnAssertionForOneUpstreamNamesTheOtherUpstreamsOrigin (0.07s)
--- PASS: TestTwoAssertionsForTheSameCallerDiffer (0.15s)
--- PASS: TestAnAssertionLifetimeNobodyMayExceedIsARefusalToBoot (0.01s)
--- PASS: TestTheAssertionCarriesOnlyTheDeclaredClaims (0.08s)
--- PASS: TestADeclaredClaimTheTokenDoesNotCarryIsOmittedRatherThanInvented (0.07s)
--- PASS: TestTheSubjectCrossesWhenTheDeclaredSetDoesNotNameIt (0.15s)
--- PASS: TestNoAssertionIsMintedWithoutAMinterOrWithoutADeclaration (0.06s)
--- PASS: TestAPublicEntryIsRefusedAnAssertionEvenByATableThatBootWouldHaveRefused (0.16s)
--- PASS: TestThePublishedJWKCarriesOnlyThePublicHalf (0.10s)
--- PASS: TestTheKeyIdIsTheThumbprintUnlessAnOperatorNamedOne (0.02s)
--- PASS: TestAMinterWhoseTwoHalvesDisagreeIsARefusalToBoot (0.16s)
--- PASS: TestAMalformedAssertionKeyIsARefusalToBoot (0.04s)
--- PASS: TestAMalformedAssertionIssuerIsARefusalToBoot (0.01s)
--- PASS: TestTheProblemEnvelopeIsTheReferencesFieldOrder (0.00s)
--- PASS: TestAValidationFailureKeepsFieldBeforeCodeAndIsLast (0.00s)
--- PASS: TestACrossOriginPostIsRefusedAndIdentityIsNeverAsked (0.00s)
--- PASS: TestASameOriginPostSucceeds (0.00s)
--- PASS: TestOnlySameOriginSecFetchSitePasses (0.00s)
--- PASS: TestOriginIsComparedByHostNotByScheme (0.00s)
--- PASS: TestARequestThatStatesNeitherHeaderIsRefused (0.00s)
--- PASS: TestDisagreeingOriginSignalsAreRefused (0.00s)
--- PASS: TestTheReadIsNotGated (0.00s)
--- PASS: TestAHeaderSentTwiceTakesTheFirstValue (0.00s)
--- PASS: TestTheParameterRefusalIsUnreachableForTheDeclaredHeaders (0.00s)
--- PASS: TestTheSessionCookieIsTheHostPrefixedContract (0.00s)
--- PASS: TestClearingTheCookieRepeatsEveryAttribute (0.00s)
--- PASS: TestTwoRefusalCausesProduceIdenticalResponses (0.00s)
--- PASS: TestTheTwoRefusalsAgreeOnStatusAndContentType (0.00s)
--- PASS: TestALockedAccountIs423AndItsRetryAfterTravels (0.00s)
--- PASS: TestMeProxiesWithTheStoredTokenAndReturnsOnlyTheAccount (0.00s)
--- PASS: TestAnExpiredSessionIs401AndIdentityIsNeverAsked (0.00s)
--- PASS: TestAWithdrawnSessionIs401AndTheRecordIsDropped (0.00s)
--- PASS: TestAForgottenSessionIs401AndTheCookieIsCleared (0.00s)
--- PASS: TestAnIdentityOutageIs503AndTheSessionSurvivesIt (0.00s)
--- PASS: TestSignOutRevokesLocallyAndUpstream (0.00s)
--- PASS: TestSignOutWithNoCookieIs401 (0.00s)
--- PASS: TestSigningOutWithAForgottenCookieIs204AndStillClears (0.00s)
--- PASS: TestSigningOutAnAlreadyRevokedSessionIs204 (0.00s)
--- PASS: TestSigningOutWhileIdentityIsDownStillSignsOutAndSays503 (0.00s)
--- PASS: TestANonRevokingLogoutIsUnreachableNotUnusable (0.00s)
--- PASS: TestAStoreThatIsDownIs503Not401 (0.00s)
--- PASS: TestEveryLoginMintsAFreshSessionId (0.00s)
--- PASS: TestTheCookieIsTheKeyTheRecordIsStoredUnder (0.00s)
--- PASS: TestRegisterReturnsTheAccountAndNoCookie (0.00s)
--- PASS: TestTheCallersBodyReachesIdentityVerbatim (0.00s)
--- PASS: TestMalformedBodiesAreRefusedAndIdentityIsNeverAsked (0.00s)
--- PASS: TestABodyJustInsideTheCapIsForwarded (0.00s)
--- PASS: TestIdentitysRegistrationRefusalsAreMapped (0.00s)
--- PASS: TestAnUnreachableIdentityIs503AndNamesNoHost (0.00s)
--- PASS: TestAPanickingIdentityIsA503AndNotADeadGateway (0.00s)
--- PASS: TestAHungIdentityIsBounded (0.06s)
--- PASS: TestASessionWithNoUsableExpiryIsRefusedAndNothingIsStored (0.00s)
--- PASS: TestTheLoginBodyCarriesTheExpiryAndNothingElse (0.00s)
--- PASS: TestAMalformedIdentityURLIsARefusalToBuild (0.00s)
--- PASS: TestATrailingSlashIsDropped (0.00s)
--- PASS: TestTheTimeoutIsValidatedAndZeroMeansTheDefault (0.00s)
--- PASS: TestABrowserSurfaceWithNoSessionStoreIsARefusalToBuild (0.00s)
--- PASS: TestWithoutABrowserSurfaceTheFourRoutesAre404 (0.00s)
--- PASS: TestABrowserSurfaceRegistersNoProbeAndTheReferenceAgrees (0.00s)
--- PASS: TestARegisteredIdentityProbeReportsByNameAndNeverByReason (0.00s)
--- PASS: TestTheBrowserNeverReceivesTheIdentityToken (0.00s)
--- PASS: TestTheOriginGateCoversEveryMutatingRouteAndOnlyThose (0.00s)
--- PASS: TestNoFileInThisPackageTalksToARealSocket (0.02s)
--- PASS: TestLivenessAnswersOkWithTheDocumentsShape (0.00s)
--- PASS: TestReadinessWithNoProbesAnswersAnEmptyObjectNotNull (0.00s)
--- PASS: TestReadinessNamesTheDependencyThatIsDownAndNotWhyItIsDown (0.00s)
--- PASS: TestReadinessRendersDependenciesInTheOrderTheyWereRegistered (0.00s)
--- PASS: TestAProbeThatPanicsIsOneUnavailableDependency (0.00s)
--- PASS: TestAProbeThatIgnoresItsContextIsStillBounded (0.05s)
--- PASS: TestTheTimeoutIsOnlyEverLoweredInATest (0.00s)
--- PASS: TestEveryRouteRefusalIsTheV0NotFoundEnvelope (0.00s)
--- PASS: TestHeadOnAProbePathAnswersTheSameAsGet (0.00s)
--- PASS: TestEveryOperationIsEitherServedOrDeclined (0.00s)
--- PASS: TestTwoAppsCoexistInOneProcess (0.00s)
--- PASS: TestExactlyOneFileInThisPackageTouchesTheProcessEnvironment (0.00s)
--- PASS: TestRuntimeOptionsBuildsAnAddressAndHandsNewItsOptions (0.00s)
--- PASS: TestAnUnreadablePortIsARefusalToBoot (0.00s)
--- PASS: TestAConfigurationItCannotServeIsRefusedAtConstruction (0.00s)
--- PASS: TestAValidConfigurationIsNotRefused (0.00s)
--- PASS: TestAProblemIsTheDocumentedEnvelope (0.00s)
--- PASS: TestTheTraceIdHeaderEqualsTheBodyAndLooksLikeOne (0.00s)
--- PASS: TestFieldErrorsAppearOnlyOnA422 (0.00s)
--- PASS: TestTheInstanceIsThePathAndTheQueryNeverReachesTheBody (0.00s)
--- PASS: TestACodeWithNoTitleIsRefusedRatherThanRendered (0.00s)
--- PASS: TestEveryProblemCodeHasATitle (0.00s)
--- PASS: TestTheV0EnvelopeCarriesOnlyTheTwoFieldsTheDocumentDeclares (0.00s)
--- PASS: TestADependencyNameWithAwkwardCharactersIsEscaped (0.00s)
--- PASS: TestTheCallersCredentialNeverReachesAnInternalService (0.00s)
--- PASS: TestAnEntryWithNoTokenIsReachedWithNoAuthorizationAtAll (0.00s)
--- PASS: TestOnlyContentTypeAndAcceptCrossToTheService (0.00s)
--- PASS: TestABodyIsStreamedAndItsContentTypeCrossesWithIt (0.00s)
--- PASS: TestTheRequestAllowlistIsExactlyTwoNames (0.00s)
--- PASS: TestTheResponseAllowlistIsExactlyOneName (0.00s)
--- PASS: TestARedirectIsNeitherFollowedNorRelayed (0.00s)
--- PASS: TestAnUpstreamThatHangsIsA503AndNotAHungGateway (0.05s)
--- PASS: TestTheRelayDropsSetCookieAndSetsNoStore (0.00s)
--- PASS: TestAnUpstreamsOwnCacheControlIsOverriddenNotForwarded (0.00s)
--- PASS: TestOnlyA2xxOrA4xxIsRelayed (0.01s)
--- PASS: TestTheTwoServiceFailuresAreDifferentSentencesAndDifferentLogLines (0.00s)
--- PASS: TestTheLogNamesTheShapeOfAnAnswerAndNeverItsBody (0.00s)
--- PASS: TestTheShapeOfAnAnswerTellsJsonFromNullFromText (0.00s)
--- PASS: TestAResponseWithNoContentTypeIsRelayedAsOctetStreamNotSniffed (0.00s)
--- PASS: TestAnAnonymousCallerToAPrivateRouteGets401AndTheUpstreamIsNeverContacted (0.00s)
--- PASS: TestARequestTheAuthGateRefusedIsNotCounted (0.00s)
--- PASS: TestARequestTheAuthGateAcceptedIsCounted (0.00s)
--- PASS: TestADoubledHeaderIsReducedBeforeTheGatesOnAForwardedRequest (0.00s)
--- PASS: TestAPublicRouteIsStillMountedAndTheProbesStillAnswerWithoutACredential (0.00s)
--- PASS: TestACredentialTheGateEstablishedReachesThePassThrough (0.00s)
--- PASS: TestGatewayOwnsItsOwnRouteEvenUnderTheBroadestPrefix (0.00s)
--- PASS: TestAnAssertionSigningFailureIsGatewayOwns503AndTheServiceIsNotAsked (0.00s)
--- PASS: TestTheQueryCrossesVerbatimAndTheDestinationIsTheTables (0.00s)
--- PASS: TestARelayedNoContentKeepsItsEmptyBody (0.00s)
--- PASS: TestTheQueryIsAppendedVerbatimAndABareQuestionMarkSurvives (0.00s)
--- PASS: TestRoutedTrafficIsCountedAndARoutedRefusalNeverReachesTheService (0.00s)
--- PASS: TestAnUnreachableCounterStoreServesRoutedTrafficUncountedAndIsNamedInReadiness (0.00s)
--- PASS: TestTheRouterServesExactlyWhatTheGeneratedDocumentDeclares (0.00s)
--- PASS: TestTheHeadRoutesAreTheProbePaths (0.00s)
--- PASS: TestTheServerImplementsEveryOperationTheDocumentDeclares (0.00s)
--- PASS: TestEveryShippedRouteDrawsItsOwnNamedAllowance (0.04s)
--- PASS: TestLoginIsNotAnsweredUnderTheDefaultAllowance (0.00s)
--- PASS: TestTheLoginAllowanceIsEnforcedAndNotJustAnnounced (0.00s)
--- PASS: TestExhaustingOneAuthBudgetLeavesTheOtherSpendingItsOwn (0.00s)
--- PASS: TestARouteThatMerelySharesANameDoesNotInheritItsAllowance (0.00s)
--- PASS: TestTheProbePathsAreStillNeverCounted (0.03s)
--- PASS: TestTheConstructorAllowanceDoesNotOverrideAnEntryTheTableNames (0.00s)
--- PASS: TestARouteTableIsReadFromTheEnvironmentAndAnUnsetOneIsNoRouting (0.00s)
--- PASS: TestAMalformedRouteTableVariableIsARefusalToBoot (0.00s)
--- PASS: TestTheAssertionKeyIsReadFromTheEnvironmentAndNothingElseIs (0.07s)
--- PASS: TestAGatewayBuiltFromTheEnvironmentRefusesAnAnonymousRequestBeforeTheUpstream (0.00s)
--- PASS: TestAPublicRouteStillAnswersForAnAnonymousCallerOnAGatewayWithAVerifier (0.28s)
--- PASS: TestTheWholeRuntimeConfigurationComposes (0.06s)
--- PASS: TestTheKeyFileIsReadAtStartupRatherThanPerRequest (0.07s)
--- PASS: TestTheTestKeyFixtureIsAnRSAKeyPair (0.06s)
--- PASS: TestARuntimeGatewaySignsInAndReadsItsOwnSession (0.03s)
--- PASS: TestASessionSurvivesTheProcessThatCreatedIt (0.03s)
--- PASS: TestANoStoreMeansNoBrowserSurfaceRatherThanADegradedOne (0.00s)
--- PASS: TestAnUnconfiguredGatewayDeclinesTheFourRoutesAsTheReferenceDoes (0.00s)
--- PASS: TestAConfiguredBrowserSurfaceAnswersItsOwnRoutesRatherThanDecliningThem (0.03s)
--- PASS: TestAnUnusableIdentityURLIsARefusalToBoot (0.00s)
--- PASS: TestTheRuntimeReaderReadsExactlyTheseVariables (0.00s)
--- PASS: TestTheProbeOrderIsIdentityThenRedis (0.00s)
--- PASS: TestAProxiedGatewayVerifiesARealToken (0.04s)
--- PASS: TestABadRouteTableIsARefusalToConstructTheGateway (0.00s)
--- PASS: TestTheJSONASpellingAnOperatorGetsWrongIsAlsoARefusal (0.00s)
--- PASS: TestAValidRouteTableIsNotRefused (0.00s)
--- PASS: TestAValidatedTableIsACopyTheCallerCannotReachInto (0.00s)
--- PASS: TestUpstreamPathRebuildsEverySegmentAndRefusesWhatItCannotExpress (0.00s)
--- PASS: TestUpstreamPathWouldBePathCleanIfItWereAFilter (0.00s)
--- PASS: TestTheNormalisedPathIsTheURLParsersOwn (0.00s)
--- PASS: TestTheLongestPrefixWinsOnASegmentBoundary (0.00s)
--- PASS: TestAPublicRouteIsDecidedByTheSameResolverThatDecidesTheDestination (0.00s)
--- PASS: TestAResolvedRouteIsACopyOfItsClaims (0.00s)
--- PASS: TestAPublicRouteIsAcceptedWithNothingButAnOrigin (0.00s)
--- PASS: TestAnEmptyRouteTableVariableIsNoRoutingAtAll (0.00s)
--- PASS: TestEveryRouteTableRefusalNamesItsOwnRule (0.00s)
--- PASS: TestAnEntryWithNothingButAnOriginIsTheDefaultShape (0.00s)
--- PASS: TestTheQueryIsAppendedVerbatim (0.00s)
--- PASS: TestWithTelemetryOffARequestIsAnsweredAsBeforeAndNothingIsRecorded (0.00s)
--- PASS: TestTheRequestOpensOneServerSpanNamedByTheFleetsGrammar (0.00s)
--- PASS: TestTheProcessIdentityIsOnTheResourceAndNotOnTheSpan (0.00s)
--- PASS: TestAFailureCarriesCoreErrorVocabularyAndARefusalDoesNot (0.00s)
--- PASS: TestAValidTraceparentIsContinuedAndAGarbageOneIsIgnored (0.00s)
ok  	github.com/cafaye/gateway/internal/httpapi	4.543s
--- PASS: TestTheBucketOrderIsAccountThenAPIKeyThenAddress (0.00s)
--- PASS: TestTheAccountIsTheClaimThenTheClaimFieldThenTheSubject (0.00s)
--- PASS: TestTrustedProxiesDefaultsToTheSocketPeerAndTheDefaultIsNotAProxyCount (0.00s)
--- PASS: TestAnEntryIsParsedAsAnAddressAndNotMatchedForSafeCharacters (0.00s)
--- PASS: TestNoHeaderValueBecomesABucket (0.00s)
--- PASS: TestRedisDownFailsOpenAndABrokenConfigurationFailsClosed (0.00s)
--- PASS: TestOneAtomicStepAdmitsExactlyTheLimitUnderABurst (0.00s)
--- PASS: TestEveryRateLimitFieldIsAnnouncedOnEveryAnsweredRequest (0.00s)
--- PASS: TestTheTwoProbePathsAreNeverCounted (0.00s)
--- PASS: TestTheShippedTableIsWholeAndStrict (0.00s)
--- PASS: TestEveryShippedPrefixIsAPathAndNotAPattern (0.00s)
--- PASS: TestTheShippedTableIsTheOneTheReferenceShips (0.00s)
--- PASS: TestNoTwoShippedPrefixesAreTheSameString (0.00s)
--- PASS: TestTheDefaultRowIsTheLimitersOwnDefault (0.00s)
--- PASS: TestTheShippedTableIsNotSharedBetweenCallers (0.00s)
--- PASS: TestLoginIsTheStrictestThingGatewayServes (0.00s)
--- PASS: TestRegisterIsStrictInItsOwnRightNotTheLoginBudget (0.00s)
--- PASS: TestBruteForcingALoginDoesNotSpendTheRegistrationAllowance (0.00s)
--- PASS: TestLogoutHasItsOwnBucket (0.00s)
--- PASS: TestAnyOtherAuthRouteFallsBackToTheAuthAdjacentDefault (0.00s)
--- PASS: TestV1UsesTheGeneralAPIAllowance (0.00s)
--- PASS: TestV1APIKeysIsItsOwnTighterSurface (0.00s)
--- PASS: TestAnythingUnrecognisedFallsBackToTheDefault (0.00s)
--- PASS: TestAPrefixMustEndAtAPathSegmentBoundary (0.00s)
--- PASS: TestASubpathUnderAPrefixDrawsThatPrefix (0.00s)
--- PASS: TestTheLongestMatchingPrefixWins (0.00s)
--- PASS: TestTwoPrefixesOfEqualLengthCannotBothClaimAPath (0.00s)
--- PASS: TestDefaultIsTheFallbackAndRootDoesNotTakeThatJobAway (0.00s)
--- PASS: TestAQueryStringDoesNotChangeWhichEntryApplies (0.00s)
--- PASS: TestAnEmptyTableIsTheDefaultAndDoesNotFail (0.00s)
--- PASS: TestValidationAcceptsTheShippedTable (0.00s)
--- PASS: TestValidationRefusesABadNumberOrName (0.00s)
--- PASS: TestValidationRefusesAPrefixThatIsAPattern (0.00s)
--- PASS: TestValidationAcceptsAPrefixOutsideTheV1Surface (0.00s)
--- PASS: TestValidationReturnsACopyRatherThanTheCallersMap (0.00s)
--- PASS: TestTheResolverGivesTheLimiterANameAndTheNumbersBehindIt (0.00s)
--- PASS: TestANameTheTableDoesNotCarryIsNotResolved (0.00s)
--- PASS: TestTwoEntriesSharingANameMustAgreeOnTheirNumbers (0.00s)
--- PASS: TestARouteReusingTheDefaultsNameWithTheSameNumbersIsAccepted (0.00s)
--- SKIP: TestARealServerAnswersPingWithPong (0.00s)
--- SKIP: TestTheReplyDecoderReadsTheThreeShapesTheScriptCanProduce (0.00s)
--- SKIP: TestTheScriptAnswersFourIntegers (0.00s)
--- SKIP: TestAnErrorReplyFailsOneCommandAndNotTheConnection (0.00s)
--- SKIP: TestAnErrorReplyLeavesAStoreThatKeepsCounting (0.00s)
--- PASS: TestAnUnreachableServerThrowsRatherThanResolving (0.00s)
--- SKIP: TestTheScriptAndTheMemoryStoreAnswerTheSameRequest (0.00s)
--- SKIP: TestTheScriptAndTheMemoryStoreAgreeAcrossRandomisedLimits (0.00s)
--- SKIP: TestABurstFiredAtOnceAdmitsExactlyTheLimit (0.00s)
--- SKIP: TestTwoStoresOnTwoConnectionsShareOneBucket (0.00s)
--- SKIP: TestABucketSurvivesLosingTheConnectionItWasCountedIn (0.00s)
--- SKIP: TestTheScriptExpiresItsOwnKey (0.00s)
--- SKIP: TestARefusedRequestLeavesTheStoredDebtWhereAnAdmittedOneLeftIt (0.00s)
--- SKIP: TestTheBucketCharsetIsEnforcedAgainstARealServer (0.00s)
--- PASS: TestTheTwoCountersAgreeRequestForRequest (0.00s)
--- PASS: TestTheInstantsAreWhereTheArithmeticPutsThem (0.00s)
--- PASS: TestTheTranscriptionIsTheScript (0.00s)
--- PASS: TestTheMemoryStoreSweepsOnlySettledBuckets (0.00s)
ok  	github.com/cafaye/gateway/internal/ratelimit	2.733s
?   	github.com/cafaye/gateway/internal/session	[no test files]
--- PASS: TestARoundTripThroughRedisPutsTheSessionUnderGatewaySess (0.00s)
--- PASS: TestAnAbsentSessionIsNilAndNotAnError (0.00s)
--- PASS: TestTheExpiryBoundaryIsInclusive (0.00s)
--- PASS: TestAnAlreadyExpiredSessionIsStoredAndReadsBackAsAbsent (0.00s)
--- PASS: TestCallerSuppliedBytesNeverReachAKey (0.00s)
--- PASS: TestPutRefusesAnIdGatewayDidNotMint (0.00s)
--- PASS: TestDeleteOfAnAbsentSessionSucceeds (0.00s)
--- PASS: TestAWriteThatDidNotReportSuccessIsAnError (0.00s)
--- PASS: TestAStoredSessionThatIsNotReadableIsNotAnAbsence (0.00s)
--- PASS: TestAnUnreachableStoreIsAnErrorOnEveryMethod (0.00s)
--- PASS: TestTheErrorMessagesNeverCarryTheToken (0.00s)
--- PASS: TestConstructionRefuses (0.00s)
--- PASS: TestTheShippedBinaryLinksThisStore (0.08s)
ok  	github.com/cafaye/gateway/internal/sessionredis	3.069s
--- PASS: TestNoProductionFileImportsTheSessionDouble (0.06s)
ok  	github.com/cafaye/gateway/internal/sessiontest	3.582s
--- PASS: TestNoAllowlistedAttributeNameNamesContent (0.00s)
--- PASS: TestTheAllowlistAndItsOrderListAreTheSameSet (0.00s)
--- PASS: TestProhibitedMeasurementsAreOnNoSignalAndTheirIdentifiersAreOnTheResource (0.00s)
--- PASS: TestIdentityIsOnTheResourceAndNoSignalAllowlistCarriesItButLogs (0.00s)
--- PASS: TestMetricsAreCoarserThanTracesOnPurpose (0.00s)
--- PASS: TestTheSwitchesTurnSignalsOff (0.00s)
--- PASS: TestEndpointPrefersTheCafayeName (0.00s)
--- PASS: TestASpanNameCannotHoldAnIdentifier (0.00s)
--- PASS: TestTheDefaultIsDeny (0.00s)
--- PASS: TestValuesAreConstrainedNotJustNames (0.00s)
--- PASS: TestARouteIsBoundedEvenThoughItsPatternAcceptsAConcretePath (0.00s)
--- PASS: TestEveryAllowlistedIntegerStaysInsideTheSafeJSONRange (0.00s)
--- PASS: TestTheServiceIdentityMatchesTheManifest (0.00s)
ok  	github.com/cafaye/gateway/internal/telemetry	4.158s
?   	github.com/cafaye/gateway/internal/testkeys	[no test files]
ratelimit: DID NOT RUN — ratelimit: DID NOT RUN — GATEWAY_REDIS_URL is unset. Set GATEWAY_REDIS_URL=redis://127.0.0.1:6379 to run the GCRA script against a real server, or GATEWAY_REDIS_REQUIRED=1 to make this a failure.
skips: 13 of 13 declared (all of them the live Redis tier), and 1 t.Skip() call site

==> the generated server matches the OpenAPI document
  stripbaseurl: rewrote 7 route registration(s) in api.gen.go
internal/api/api.gen.go regenerates byte-identically from openapi/v1.yaml, carries the v2.8.0 header, and its registrations are readable

suite: 252 passed, 0 failed
packages: 8 with tests

==> ok

== prime ok
```

## What was not touched

- `account_scope.yml`, `tenancy.yml`, the tenancy checker — untouched, as
  instructed; the branch carries no conflict with W35's tenancy declaration.
- No process was killed; OrbStack keeps `*:8080`, and the fixed test no longer
  cares what holds that port.
- No other test was weakened, deleted, or skipped. The 13 skips are the
  pre-existing live Redis tier (`GATEWAY_REDIS_URL` unset), reported by the
  gate as expected.
- Not merged, not pushed — the manager gates the merged result.
