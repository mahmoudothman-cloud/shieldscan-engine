package zap

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAjaxSpiderDuration(t *testing.T) {
	assert.Equal(t, 8*time.Minute, ajaxSpiderDuration("standard"))
	assert.Equal(t, 8*time.Minute, ajaxSpiderDuration(""))
	assert.Equal(t, 15*time.Minute, ajaxSpiderDuration("deep"))
}

func TestRunAjaxSpider_HappyPath(t *testing.T) {
	stub := newStubZAPServer(t)
	c := newStubClient(t, stub)
	n, err := runAjaxSpider(context.Background(), c, "https://example.com/", 8*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, 42, n)
	assert.Equal(t, "https://example.com/", stub.lastAjaxURL)
	assert.Equal(t, "8", stub.lastAjaxMaxMinutes)
}

func TestRunAjaxSpider_NotAccepted(t *testing.T) {
	stub := newStubZAPServer(t)
	stub.ajaxSpiderFails = true
	c := newStubClient(t, stub)
	_, err := runAjaxSpider(context.Background(), c, "https://example.com/", time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not accepted")
}

func TestAjaxSpiderStoppedPredicate(t *testing.T) {
	done, err := ajaxSpiderStoppedPredicate([]byte(`{"status":"stopped"}`))
	require.NoError(t, err)
	assert.True(t, done)
	done, err = ajaxSpiderStoppedPredicate([]byte(`{"status":"running"}`))
	require.NoError(t, err)
	assert.False(t, done)
}
