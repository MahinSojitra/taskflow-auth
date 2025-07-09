const Client = require("../models/Client");
const logger = require("../utils/logger");

class ClientController {
  // Register new OAuth2 client
  async registerClient(req, res) {
    try {
      const clientData = req.body;
      const owner = req.user._id;

      // Create new client
      const client = new Client({
        ...clientData,
        owner,
      });

      await client.save();

      logger.info("OAuth2 client registered successfully", {
        clientId: client.clientId,
        ownerId: owner,
        clientType: client.clientType,
      });

      res.status(201).json({
        message: "Client registered successfully",
        client: {
          id: client._id,
          name: client.name,
          clientId: client.clientId,
          clientSecret: client.clientSecret, // Only shown once
          clientType: client.clientType,
          redirectUris: client.redirectUris,
          scopes: client.scopes,
          grantTypes: client.grantTypes,
          responseTypes: client.responseTypes,
          requirePKCE: client.requirePKCE,
          createdAt: client.createdAt,
        },
      });
    } catch (error) {
      logger.error("Client registration failed:", error);
      res.status(500).json({
        error: "client_registration_failed",
        error_description: "Failed to register client",
      });
    }
  }

  // Get all clients for the authenticated user
  async getMyClients(req, res) {
    try {
      const {
        page = 1,
        limit = 10,
        sort = "createdAt",
        order = "desc",
      } = req.query;
      const skip = (page - 1) * limit;

      const sortOptions = {};
      sortOptions[sort] = order === "desc" ? -1 : 1;

      const clients = await Client.find({ owner: req.user._id })
        .select("-clientSecret") // Don't include secrets in list
        .sort(sortOptions)
        .skip(skip)
        .limit(parseInt(limit));

      const total = await Client.countDocuments({ owner: req.user._id });

      res.json({
        clients,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit),
        },
      });
    } catch (error) {
      logger.error("Get clients failed:", error);
      res.status(500).json({
        error: "clients_fetch_failed",
        error_description: "Failed to fetch clients",
      });
    }
  }

  // Get specific client by ID
  async getClient(req, res) {
    try {
      const { id } = req.params;

      const client = await Client.findOne({
        _id: id,
        owner: req.user._id,
      }).select("-clientSecret");

      if (!client) {
        return res.status(404).json({
          error: "client_not_found",
          error_description: "Client not found",
        });
      }

      res.json({
        client,
      });
    } catch (error) {
      logger.error("Get client failed:", error);
      res.status(500).json({
        error: "client_fetch_failed",
        error_description: "Failed to fetch client",
      });
    }
  }

  // Update client
  async updateClient(req, res) {
    try {
      const { id } = req.params;
      const updates = req.body;

      const client = await Client.findOne({
        _id: id,
        owner: req.user._id,
      });

      if (!client) {
        return res.status(404).json({
          error: "client_not_found",
          error_description: "Client not found",
        });
      }

      // Update allowed fields
      const allowedFields = [
        "name",
        "description",
        "redirectUris",
        "scopes",
        "grantTypes",
        "responseTypes",
        "requirePKCE",
        "codeChallengeMethods",
        "allowedOrigins",
        "website",
        "privacyPolicy",
        "termsOfService",
      ];

      for (const field of allowedFields) {
        if (updates[field] !== undefined) {
          client[field] = updates[field];
        }
      }

      await client.save();

      logger.info("Client updated successfully", {
        clientId: client.clientId,
        ownerId: req.user._id,
      });

      res.json({
        message: "Client updated successfully",
        client: {
          id: client._id,
          name: client.name,
          clientId: client.clientId,
          clientType: client.clientType,
          redirectUris: client.redirectUris,
          scopes: client.scopes,
          grantTypes: client.grantTypes,
          responseTypes: client.responseTypes,
          requirePKCE: client.requirePKCE,
          updatedAt: client.updatedAt,
        },
      });
    } catch (error) {
      logger.error("Client update failed:", error);
      res.status(500).json({
        error: "client_update_failed",
        error_description: "Failed to update client",
      });
    }
  }

  // Regenerate client secret
  async regenerateClientSecret(req, res) {
    try {
      const { id } = req.params;

      const client = await Client.findOne({
        _id: id,
        owner: req.user._id,
      });

      if (!client) {
        return res.status(404).json({
          error: "client_not_found",
          error_description: "Client not found",
        });
      }

      // Regenerate secret
      await client.regenerateClientSecret();

      logger.info("Client secret regenerated", {
        clientId: client.clientId,
        ownerId: req.user._id,
      });

      res.json({
        message: "Client secret regenerated successfully",
        clientSecret: client.clientSecret,
      });
    } catch (error) {
      logger.error("Client secret regeneration failed:", error);
      res.status(500).json({
        error: "secret_regeneration_failed",
        error_description: "Failed to regenerate client secret",
      });
    }
  }

  // Delete client
  async deleteClient(req, res) {
    try {
      const { id } = req.params;

      const client = await Client.findOne({
        _id: id,
        owner: req.user._id,
      });

      if (!client) {
        return res.status(404).json({
          error: "client_not_found",
          error_description: "Client not found",
        });
      }

      // Revoke all tokens for this client
      const Token = require("../models/Token");
      await Token.revokeClientTokens(client.clientId, "Client deleted");

      // Delete the client
      await client.deleteOne();

      logger.info("Client deleted successfully", {
        clientId: client.clientId,
        ownerId: req.user._id,
      });

      res.json({
        message: "Client deleted successfully",
      });
    } catch (error) {
      logger.error("Client deletion failed:", error);
      res.status(500).json({
        error: "client_deletion_failed",
        error_description: "Failed to delete client",
      });
    }
  }

  // Get client statistics
  async getClientStats(req, res) {
    try {
      const { id } = req.params;

      const client = await Client.findOne({
        _id: id,
        owner: req.user._id,
      });

      if (!client) {
        return res.status(404).json({
          error: "client_not_found",
          error_description: "Client not found",
        });
      }

      const Token = require("../models/Token");
      const tokenStats = await Token.getStats();

      const stats = {
        client: {
          id: client._id,
          name: client.name,
          clientId: client.clientId,
          clientType: client.clientType,
          isActive: client.isActive,
          usageCount: client.usageCount,
          lastUsed: client.lastUsed,
          createdAt: client.createdAt,
        },
        tokens: tokenStats,
        totalTokens: tokenStats.reduce((sum, stat) => sum + stat.count, 0),
        activeTokens: tokenStats.reduce(
          (sum, stat) => sum + stat.activeCount,
          0
        ),
      };

      res.json(stats);
    } catch (error) {
      logger.error("Get client stats failed:", error);
      res.status(500).json({
        error: "stats_fetch_failed",
        error_description: "Failed to fetch client statistics",
      });
    }
  }

  // Search clients
  async searchClients(req, res) {
    try {
      const { q, type, page = 1, limit = 10 } = req.query;
      const skip = (page - 1) * limit;

      let query = { owner: req.user._id };

      if (q) {
        query.$or = [
          { name: { $regex: q, $options: "i" } },
          { description: { $regex: q, $options: "i" } },
        ];
      }

      if (type) {
        query.clientType = type;
      }

      const clients = await Client.find(query)
        .select("-clientSecret")
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit));

      const total = await Client.countDocuments(query);

      res.json({
        clients,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit),
        },
      });
    } catch (error) {
      logger.error("Client search failed:", error);
      res.status(500).json({
        error: "client_search_failed",
        error_description: "Failed to search clients",
      });
    }
  }

  // Get client usage analytics
  async getClientAnalytics(req, res) {
    try {
      const { id } = req.params;
      const { period = "30d" } = req.query;

      const client = await Client.findOne({
        _id: id,
        owner: req.user._id,
      });

      if (!client) {
        return res.status(404).json({
          error: "client_not_found",
          error_description: "Client not found",
        });
      }

      // Calculate date range based on period
      const now = new Date();
      let startDate;

      switch (period) {
        case "7d":
          startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
          break;
        case "30d":
          startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
          break;
        case "90d":
          startDate = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
          break;
        default:
          startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      }

      const Token = require("../models/Token");

      // Get token usage by day
      const dailyUsage = await Token.aggregate([
        {
          $match: {
            clientId: client.clientId,
            createdAt: { $gte: startDate },
          },
        },
        {
          $group: {
            _id: {
              $dateToString: { format: "%Y-%m-%d", date: "$createdAt" },
            },
            count: { $sum: 1 },
          },
        },
        {
          $sort: { _id: 1 },
        },
      ]);

      // Get token types distribution
      const tokenTypes = await Token.aggregate([
        {
          $match: {
            clientId: client.clientId,
            createdAt: { $gte: startDate },
          },
        },
        {
          $group: {
            _id: "$tokenType",
            count: { $sum: 1 },
          },
        },
      ]);

      const analytics = {
        period,
        startDate,
        endDate: now,
        dailyUsage,
        tokenTypes,
        totalTokens: dailyUsage.reduce((sum, day) => sum + day.count, 0),
        averageTokensPerDay:
          dailyUsage.length > 0
            ? dailyUsage.reduce((sum, day) => sum + day.count, 0) /
              dailyUsage.length
            : 0,
      };

      res.json(analytics);
    } catch (error) {
      logger.error("Get client analytics failed:", error);
      res.status(500).json({
        error: "analytics_fetch_failed",
        error_description: "Failed to fetch client analytics",
      });
    }
  }
}

module.exports = new ClientController();
